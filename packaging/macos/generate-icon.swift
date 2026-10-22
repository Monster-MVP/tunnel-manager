import AppKit
import Foundation

guard CommandLine.arguments.count == 2 else { exit(2) }
let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
for size in [16, 32, 64, 128, 256, 512, 1024] {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    let scale = CGFloat(size) / 1024
    NSColor(calibratedRed: 0.10, green: 0.15, blue: 0.20, alpha: 1).setFill()
    NSBezierPath(roundedRect: NSRect(x: 16 * scale, y: 16 * scale, width: 992 * scale, height: 992 * scale), xRadius: 200 * scale, yRadius: 200 * scale).fill()
    NSColor(calibratedRed: 0.22, green: 0.82, blue: 0.68, alpha: 1).setStroke()
    let left = NSBezierPath(roundedRect: NSRect(x: 185 * scale, y: 325 * scale, width: 205 * scale, height: 375 * scale), xRadius: 46 * scale, yRadius: 46 * scale)
    left.lineWidth = 50 * scale; left.stroke()
    NSColor(calibratedRed: 0.95, green: 0.72, blue: 0.28, alpha: 1).setStroke()
    let right = NSBezierPath(roundedRect: NSRect(x: 634 * scale, y: 325 * scale, width: 205 * scale, height: 375 * scale), xRadius: 46 * scale, yRadius: 46 * scale)
    right.lineWidth = 50 * scale; right.stroke()
    NSColor.white.setStroke()
    let line = NSBezierPath(); line.move(to: NSPoint(x: 386 * scale, y: 512 * scale)); line.line(to: NSPoint(x: 638 * scale, y: 512 * scale)); line.lineWidth = 60 * scale; line.stroke()
    image.unlockFocus()
    guard let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff), let png = bitmap.representation(using: .png, properties: [:]) else { exit(2) }
    if size <= 512 { try png.write(to: directory.appendingPathComponent("icon_\(size)x\(size).png")) }
    if size >= 32 { let half = size / 2; try png.write(to: directory.appendingPathComponent("icon_\(half)x\(half)@2x.png")) }
}
