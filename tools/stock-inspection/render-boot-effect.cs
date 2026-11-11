using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;

// Offline rendering of our own artwork. The original provides only the
// column reveal/brightness envelope; no Positivo artwork is copied to output.
public static class CentralBootEffect {
    static byte[] Pixels(Bitmap bitmap) {
        using (var rgb = new Bitmap(bitmap.Width, bitmap.Height, PixelFormat.Format32bppArgb)) {
            using (var g = Graphics.FromImage(rgb)) g.DrawImageUnscaled(bitmap, 0, 0);
            var bits = rgb.LockBits(new Rectangle(0, 0, rgb.Width, rgb.Height), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            try {
                if (bits.Stride != rgb.Width * 4) throw new Exception("Unexpected pixel stride");
                var bytes = new byte[bits.Stride * rgb.Height];
                Marshal.Copy(bits.Scan0, bytes, 0, bytes.Length);
                return bytes;
            } finally { rgb.UnlockBits(bits); }
        }
    }
    static double[] Columns(byte[] bytes) {
        var values = new double[600];
        for (int y = 420; y < 600; y++) for (int x = 0; x < 600; x++) {
            int p = (y * 600 + x) * 4;
            values[x] += bytes[p] + bytes[p + 1] + bytes[p + 2];
        }
        return values;
    }
    public static void Render(string sourceZip, string artworkPath, string output) {
        using (var zip = ZipFile.OpenRead(sourceZip))
        using (var artwork = new Bitmap(artworkPath)) {
            if (artwork.Width != 600 || artwork.Height != 1024) throw new Exception("Artwork geometry mismatch");
            var names = zip.Entries.Where(e => e.FullName.StartsWith("part0/") && e.FullName.EndsWith(".png"))
                .OrderBy(e => e.FullName, StringComparer.Ordinal).ToArray();
            if (names.Length != 167) throw new Exception("Reference count mismatch");
            double[] reference;
            using (var stream = names[names.Length - 1].Open()) using (var bitmap = new Bitmap(stream)) reference = Columns(Pixels(bitmap));
            var art = Pixels(artwork);
            Directory.CreateDirectory(output);
            for (int frame = 0; frame < names.Length; frame++) {
                double[] values;
                using (var stream = names[frame].Open()) using (var bitmap = new Bitmap(stream)) {
                    if (bitmap.Width != 600 || bitmap.Height != 1024) throw new Exception("Reference geometry mismatch");
                    values = Columns(Pixels(bitmap));
                }
                var mask = new double[600];
                for (int x = 0; x < 600; x++) mask[x] = reference[x] > 100 ? Math.Min(1.15, values[x] / reference[x]) : -1;
                // Interpolate between letter columns so our different typography
                // receives a continuous reveal, rather than the source glyphs.
                for (int x = 0; x < 600; x++) if (mask[x] < 0) {
                    int left = x - 1, right = x + 1;
                    while (left >= 0 && reference[left] <= 100) left--;
                    while (right < 600 && reference[right] <= 100) right++;
                    if (left < 0 && right >= 600) mask[x] = 0;
                    else if (left < 0) mask[x] = mask[right];
                    else if (right >= 600) mask[x] = mask[left];
                    else mask[x] = mask[left] + (mask[right] - mask[left]) * (x - left) / (right - left);
                }
                // Smooth only the spatial envelope, preserving frame timing.
                var smooth = new double[600];
                for (int x = 0; x < 600; x++) {
                    int n = 0;
                    for (int dx = -4; dx <= 4; dx++) if (x + dx >= 0 && x + dx < 600) { smooth[x] += mask[x + dx]; n++; }
                    smooth[x] /= n;
                }
                using (var result = new Bitmap(600, 1024, PixelFormat.Format32bppArgb)) {
                    var pixels = new byte[art.Length];
                    for (int y = 0; y < 1024; y++) for (int x = 0; x < 600; x++) {
                        int p = (y * 600 + x) * 4;
                        for (int c = 0; c < 3; c++) pixels[p + c] = (byte)Math.Min(255, Math.Round(art[p + c] * smooth[x]));
                        pixels[p + 3] = 255;
                    }
                    var bits = result.LockBits(new Rectangle(0, 0, 600, 1024), ImageLockMode.WriteOnly, PixelFormat.Format32bppArgb);
                    try { Marshal.Copy(pixels, 0, bits.Scan0, pixels.Length); } finally { result.UnlockBits(bits); }
                    result.Save(Path.Combine(output, "frame-" + frame.ToString("D3") + ".png"), ImageFormat.Png);
                }
            }
        }
    }
}
