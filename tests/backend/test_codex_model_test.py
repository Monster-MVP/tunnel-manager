"""Synthetic-only model tests, including API authority and generation guards."""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.api.routes import create_router
from app.api.security import SecurityManager, SecurityMiddleware
from app.monitoring.codex_credentials import SOURCE
from app.monitoring.codex_model_test import (
    REMOTE_PREVIEW_SCRIPT,
    ModelPreview,
    ModelTestResult,
    build_remote_model_preview_command,
    build_remote_model_test_command,
    validate_model,
    validate_model_base_url,
)
from app.schemas.inputs import CodexModelPreviewInput, CodexModelTestInput
from app.tunnels.manager import EngineError, TunnelManager
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

CANARY = 'SYNTHETIC-PRIVATE-KEY-493821'
BODY_CANARY = 'SYNTHETIC-UPSTREAM-TEXT-453991'


def run_preview(home, content=None, **env):
    if content is not None:
        (home / '.codex').mkdir(parents=True, exist_ok=True)
        (home / '.codex' / 'config.toml').write_text(content)
    proc = subprocess.run([sys.executable, '-I', '-c', REMOTE_PREVIEW_SCRIPT],
                          env={'HOME': str(home), **env}, capture_output=True, timeout=5, check=False)
    assert proc.returncode == 0 and proc.stderr == b''
    assert CANARY.encode() not in proc.stdout
    return json.loads(proc.stdout), ModelPreview.from_remote(proc.stdout, 0)


def model_protocol(**updates):
    return json.dumps({'version': 1, 'state': 'SUCCESS', 'credential_state': 'READABLE',
                       'http_status': 200, 'total_ms': 2.5, 'reason_code': 'SUCCESS'} | updates).encode()


def test_preview_only_selected_fields_and_no_auth_read(tmp_path):
    config = 'model_provider = "provider"\nmodel = "gpt-5"\n[model_providers.provider]\nbase_url = "https://api.vendor.org/v1"\nwire_api = "responses"\napi_key = "' + CANARY + '"\n'
    value, result = run_preview(tmp_path, config)
    assert value == {'version': 1, 'config_state': 'READY', 'model': 'gpt-5',
                     'base_url': 'https://api.vendor.org/v1', 'wire_api': 'responses'}
    assert result.config_state == 'READY'
    assert not (tmp_path / '.codex' / 'auth.json').exists()


def test_preview_missing_unreadable_and_unsupported_distinct(tmp_path):
    assert run_preview(tmp_path)[1].config_state == 'NOT_FOUND'
    assert run_preview(tmp_path, 'model="gpt-5"', CODEX_HOME='relative')[1].config_state == 'UNREADABLE'
    assert run_preview(tmp_path, 'model_provider="azure"')[1].config_state == 'UNSUPPORTED_PROVIDER'
    assert run_preview(tmp_path, 'profile="work"\nmodel="gpt-5"')[1].config_state == 'UNSUPPORTED_PROVIDER'


@pytest.mark.parametrize('config', [
    'model_provider = 42', 'model = true', 'model = "sk-12345678901234567890"',
    'model="gpt-5"\nmodel="gpt-4"',
    'model_provider="vendor"\n[model_providers.vendor]\nbase_url="https://api.vendor.org/v1?key=secret"',
    'model_provider="vendor"\n[model_providers.vendor]\nbase_url="https://api.vendor.org/sk-12345678901234567890"',
])
def test_preview_invalid_config_never_echoes_raw(tmp_path, config):
    value, result = run_preview(tmp_path, config)
    assert result.config_state == 'INVALID_CONFIG'
    assert value['base_url'] is value['model'] is value['wire_api'] is None


@pytest.mark.parametrize('url', ['http://api.vendor.org/v1', 'https://127.0.0.1/v1', 'https://[::1]/v1',
                                'https://foo.local/v1', 'https://localhost/v1', 'https://api.vendor.org:8080/v1',
                                'https://user:pass@api.vendor.org/v1', 'https://api.vendor.org/v1?key=x',
                                'https://api.vendor.org/v1#x', 'https://api.vendor.org/../v1',
                                'https://api.vendor.org/%2e%2e', 'https://api.ven\ndor.org/v1',
                                'https://api.ven\tdor.org/v1', ' https://api.vendor.org/v1',
                                'https://api.vendor.org/sk-12345678901234567890'])
def test_destination_validator_rejects_nonpublic_ambiguous_and_secret_targets(url):
    with pytest.raises(ValueError):
        validate_model_base_url(url)


def test_model_and_url_canonicalization():
    assert validate_model_base_url('https://API.vendor.org:443/v1/') == 'https://api.vendor.org/v1'
    assert validate_model('vendor/gpt-5:latest') == 'vendor/gpt-5:latest'
    for bad in ['', 'x\nheader', '$(secret)', 'sk-12345678901234567890']:
        with pytest.raises(ValueError):
            validate_model(bad)


@pytest.mark.parametrize('changes', [
    {'state': CANARY}, {'state': 'SUCCESS', 'http_status': 401}, {'credential_state': 'NOT_CHECKED'},
    {'http_status': True}, {'total_ms': None}, {'total_ms': float('nan')}, {'total_ms': True},
    {'reason_code': 'TLS_ERROR'}, {'key': CANARY}, {'version': True},
])
def test_remote_protocol_strict_and_cannot_claim_success(changes):
    result = ModelTestResult.from_remote(model_protocol(**changes), 0).as_dict()
    assert result['state'] == 'CHECK_UNAVAILABLE' and result['reason_code'] == 'INVALID_REMOTE_RESULT'
    assert result['llm_completion_verified'] is False and CANARY not in json.dumps(result)


@pytest.mark.parametrize(('state','http','credential','reason','auth','completion'), [
    ('SUCCESS',200,'READABLE','SUCCESS','VERIFIED','SUCCEEDED'),
    ('AUTH_REJECTED',401,'READABLE','AUTH_REJECTED','REJECTED','FAILED'),
    ('PERMISSION_DENIED',403,'READABLE','PERMISSION_DENIED','UNKNOWN','FAILED'),
    ('RATE_LIMITED',429,'READABLE','RATE_LIMITED','UNKNOWN','FAILED'),
    ('INVALID_RESPONSE',200,'READABLE','INVALID_RESPONSE','UNKNOWN','FAILED'),
    ('CREDENTIAL_UNAVAILABLE',None,'OAUTH_ONLY','OAUTH_ONLY','NOT_TESTED','NOT_TESTED'),
])
def test_result_does_not_infer_auth_from_transport(state,http,credential,reason,auth,completion):
    result = ModelTestResult.from_remote(model_protocol(state=state,http_status=http,credential_state=credential,reason_code=reason),0).as_dict()
    assert result['authentication'] == auth and result['model_completion'] == completion
    assert result['llm_completion_verified'] is (state == 'SUCCESS')


def test_fixed_helper_is_bounded_no_key_or_model_injection():
    command = build_remote_model_test_command('https://api.vendor.org/v1','gpt-5','responses',17892)
    assert '/usr/bin/python3 -I -c ' in command and CANARY not in command
    assert 'max_output_tokens' in command and 'signal.alarm(20)' in command
    assert 'Reply with OK only.' in command and 'Authorization' in command
    assert build_remote_model_preview_command().startswith('if [ -x /usr/bin/python3 ]')
    with pytest.raises(ValueError):
        build_remote_model_test_command('https://api.vendor.org/v1','x; cat auth.json','responses',17892)


@pytest.fixture
def manager(repo,data_dir):
    server = repo.create_server({'name':'isolated','host':'fixture.test','user':'fixture'})
    return TunnelManager(data_dir,repo),server


def attach_handle(engine,server_id):
    handle = SimpleNamespace(generation=3,process=SimpleNamespace(returncode=None),
                             config_path=Path('/fixture-only/config'),control_socket=Path('/fixture-only/socket'),alias='fixture-only')
    engine._runs[server_id] = handle
    engine._generation[server_id] = 3
    engine._assert_owned = AsyncMock()
    engine._control_check = AsyncMock(return_value=True)
    engine._execute = AsyncMock(return_value=(0,model_protocol(),CANARY.encode()))
    return handle


async def invoke(engine,server,**updates):
    params = {'server_id':server['id'],'source':SOURCE,'consent':True,'base_url':'https://api.vendor.org/v1',
              'model':'gpt-5','wire_api':'responses','expected_revision':server['revision']} | updates
    return await engine.codex_model_test(**params)


async def test_manager_does_not_connect_no_channel_or_consent(manager):
    engine,server = manager
    engine._start_locked = AsyncMock()
    engine._execute = AsyncMock()
    result = await invoke(engine,server)
    assert result['reason_code'] == 'CONNECTION_REQUIRED'
    with pytest.raises(EngineError) as error:
        await invoke(engine,server,consent=False)
    assert error.value.code == 'CONSENT_REQUIRED'
    engine._execute.assert_not_awaited()
    engine._start_locked.assert_not_awaited()


async def test_manager_owned_revision_cooldown_and_no_secret_log(manager):
    engine,server = manager
    handle = attach_handle(engine,server['id'])
    result = await invoke(engine,server)
    assert result['state'] == 'SUCCESS' and result['authentication'] == 'VERIFIED'
    argv,timeout = engine._execute.await_args.args
    assert timeout == 25 and argv[argv.index('-S')+1] == str(handle.control_socket)
    assert 'ProxyCommand=/usr/bin/false' in argv and CANARY not in str(argv)
    assert not engine.repo.logs(server['id'])
    with pytest.raises(EngineError) as error:
        await invoke(engine,server)
    assert error.value.code == 'MODEL_TEST_COOLDOWN'
    with pytest.raises(EngineError) as error:
        await invoke(engine,server,expected_revision=server['revision']+1)
    assert error.value.code == 'REVISION_CONFLICT'
    assert engine._execute.await_count == 1


async def test_manager_generation_change_cancels_claim_and_no_ownership_reuse(manager):
    engine,server = manager
    attach_handle(engine,server['id'])
    async def changed(argv,timeout):
        engine._generation[server['id']] += 1
        return 0,model_protocol(),CANARY.encode()
    engine._execute.side_effect = changed
    result = await invoke(engine,server)
    assert result['reason_code'] == 'CONNECTION_CHANGED' and not result['llm_completion_verified']
    assert CANARY not in json.dumps(result)


async def test_manager_rechecks_revision_after_capacity_wait(manager):
    engine,server = manager
    attach_handle(engine,server['id'])
    engine._active_probes = engine._settings()['max_concurrent_probes']
    pending = asyncio.create_task(invoke(engine,server))
    await asyncio.sleep(0)
    engine.repo.update_server(server['id'],{'name':'changed'})
    async with engine._probe_condition:
        engine._active_probes = 0
        engine._probe_condition.notify_all()
    with pytest.raises(EngineError) as error:
        await pending
    assert error.value.code == 'REVISION_CONFLICT'
    engine._execute.assert_not_awaited()


async def test_manager_preview_no_auth_and_cancellation(manager):
    engine,server = manager
    attach_handle(engine,server['id'])
    output = json.dumps({'version':1,'config_state':'READY','base_url':'https://api.vendor.org/v1','model':'gpt-5','wire_api':'responses'}).encode()
    engine._execute.return_value = (0,output,b'')
    result = await engine.codex_model_preview(server['id'],SOURCE)
    assert result['profile_revision'] == server['revision'] and result['config_state'] == 'READY'
    assert 'auth.json' not in engine._execute.await_args.args[0][-1]
    engine._execute.side_effect = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await invoke(engine,server)
    assert engine._active_probes == 0 and not engine._lock(server['id']).locked()


async def test_manager_rechecks_revision_after_control_wait_before_key_read(manager):
    engine,server = manager
    attach_handle(engine,server['id'])
    async def changed_control(handle):
        engine.repo.update_server(server['id'],{'name':'changed while control waited'})
        return True
    engine._control_check.side_effect = changed_control
    with pytest.raises(EngineError) as error:
        await invoke(engine,server)
    assert error.value.code == 'REVISION_CONFLICT'
    engine._execute.assert_not_awaited()
    assert not engine._model_test_started


async def test_manager_discards_profile_change_during_request_without_second_call(manager):
    engine,server = manager
    attach_handle(engine,server['id'])
    async def changed_request(argv,timeout):
        engine.repo.update_server(server['id'],{'name':'changed during request'})
        return 0,model_protocol(),CANARY.encode()
    engine._execute.side_effect = changed_request
    result = await invoke(engine,server)
    assert result['reason_code'] == 'CONNECTION_CHANGED' and not result['llm_completion_verified']
    assert engine._execute.await_count == 1


@pytest.fixture
def model_api(repo):
    result = {'server_id':'fixture','ownership':'MANAGED','ssh_connected':True,'observed_at':'2026-10-11T00:00:00Z',
              **ModelTestResult.from_remote(model_protocol(),0).as_dict()}
    preview = {'server_id':'fixture','ownership':'MANAGED','ssh_connected':True,'observed_at':'2026-10-11T00:00:00Z',
               'profile_revision':1,**ModelPreview('READY','https://api.vendor.org/v1','gpt-5','responses').as_dict()}
    engine = SimpleNamespace(codex_model_test=AsyncMock(return_value=result),codex_model_preview=AsyncMock(return_value=preview))
    app = FastAPI()
    security = SecurityManager('http://127.0.0.1:18401')
    app.state.security = security
    app.add_middleware(SecurityMiddleware,security=security)
    app.include_router(create_router(repo,engine))
    @app.exception_handler(HTTPException)
    async def errors(request,error):
        return JSONResponse(error.detail,status_code=error.status_code)
    with TestClient(app,base_url=security.origin) as client:
        yield client,security,engine


def authorize(client,security):
    response = client.post('/api/v1/sessions/exchange',json={'ticket':security.issue_bootstrap_ticket()})
    client.headers.update({'X-CSRF-Token':response.json()['csrf'],'Origin':security.origin})


def request_body(server):
    return {'source':SOURCE,'consent':True,'base_url':'https://api.vendor.org/v1','model':'gpt-5','wire_api':'responses','expected_revision':server['revision']}


def test_api_session_consent_revision_csrf_origin(model_api,repo):
    client,security,engine = model_api
    server = repo.create_server({'name':'fixture','host':'fixture.test','user':'fixture'})
    url = f"/api/v1/servers/{server['id']}/model-test"
    payload = request_body(server)
    assert client.post(url,json=payload).status_code == 401
    authorize(client,security)
    assert client.post(url,json=payload,headers={'Origin':'https://evil.test'}).status_code == 403
    assert client.post(url,json=payload,headers={'X-CSRF-Token':'wrong'}).status_code == 401
    assert client.post(url,json=payload|{'consent':False}).status_code == 403
    assert client.post(url,json=payload|{'expected_revision':2}).status_code == 409
    assert client.post(url,json=payload|{'key':CANARY}).status_code == 422
    engine.codex_model_test.assert_not_awaited()
    response = client.post(url,json=payload)
    assert response.status_code == 200 and response.json()['llm_completion_verified']
    engine.codex_model_test.assert_awaited_once_with(server['id'],SOURCE,True,payload['base_url'],payload['model'],'responses',1)
    audit = next(item for item in repo.activity_events() if item['action']=='server.model-test')
    assert audit['details'] == {'source':SOURCE,'state':'SUCCESS','http_status':200}


def test_api_external_ownership_preview_and_sanitized_faulty_engine(model_api,repo):
    client,security,engine = model_api
    authorize(client,security)
    external = repo.create_server({'name':'external','host':'fixture.test','user':'fixture','management':'OBSERVED_EXTERNAL'})
    url = f"/api/v1/servers/{external['id']}/model-test"
    assert client.post(url,json=request_body(external)).status_code == 403
    assert client.post(url+'/preview',json={'source':SOURCE}).status_code == 403
    engine.codex_model_test.assert_not_awaited()
    server = repo.create_server({'name':'fixture','host':'fixture.test','user':'fixture'})
    engine.codex_model_test.return_value.update(secret=CANARY,output=BODY_CANARY,authentication=CANARY)
    response = client.post(f"/api/v1/servers/{server['id']}/model-test",json=request_body(server))
    assert response.status_code == 200 and response.json()['authentication']=='VERIFIED'
    assert CANARY not in response.text and BODY_CANARY not in response.text
    engine.codex_model_test.side_effect = RuntimeError(CANARY)
    response = client.post(f"/api/v1/servers/{server['id']}/model-test",json=request_body(server))
    assert response.status_code == 503 and CANARY not in response.text
    assert CANARY not in json.dumps(repo.activity_events())


@pytest.mark.parametrize('change',[{'consent':1},{'consent':'true'},{'expected_revision':True},{'expected_revision':'1'},
                                  {'base_url':'http://api.vendor.org/v1'},{'model':CANARY+'\n'}])
def test_inputs_strict_types_and_shapes(change):
    value = {'source':SOURCE,'consent':True,'base_url':'https://api.vendor.org/v1','model':'gpt-5','wire_api':'responses','expected_revision':1}
    with pytest.raises(ValueError):
        CodexModelTestInput(**(value|change))
    with pytest.raises(ValueError):
        CodexModelPreviewInput(source=SOURCE,key=CANARY)
