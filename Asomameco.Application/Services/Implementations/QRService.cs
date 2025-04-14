using QRCoder;
using System;
using System.IO;

public class QrService
{
    public string GenerarQR(string data)
    {
        using (QRCodeGenerator qrGenerator = new QRCodeGenerator())
        {
            // Crear el código QR
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(data, QRCodeGenerator.ECCLevel.Q);
            using (PngByteQRCode qrCode = new PngByteQRCode(qrCodeData))
            {
                // Obtener los bytes de la imagen QR
                byte[] qrCodeImage = qrCode.GetGraphic(20);

                // Definir la ruta temporal para guardar el archivo PNG
                string tempFilePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".png");

                // Guardar los bytes de la imagen como un archivo PNG
                System.IO.File.WriteAllBytes(tempFilePath, qrCodeImage);

                // Devolver la ruta del archivo generado
                return tempFilePath;
            }
        }
    }

}
