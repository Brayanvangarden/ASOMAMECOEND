using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

public class EmailService
{
    private readonly IConfiguration _configuration;

    public EmailService(IConfiguration configuration)
    {
        _configuration = configuration;
    }


    public async Task EnviarCorreoConAdjuntoAsync(string destinatario, string asunto, string mensaje, string archivoAdjunto)
    {
        using (var smtp = new SmtpClient())
        {
            smtp.Host = _configuration["Smtp:Host"];
            smtp.Port = int.Parse(_configuration["Smtp:Port"]);
            smtp.Credentials = new NetworkCredential(_configuration["Smtp:User"], _configuration["Smtp:Password"]);
            smtp.EnableSsl = true;

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_configuration["Smtp:User"]),
                Subject = asunto,
                Body = mensaje,
                IsBodyHtml = true
            };

            mailMessage.To.Add(destinatario);

            // Agregar el archivo adjunto
            var attachment = new Attachment(archivoAdjunto);
            mailMessage.Attachments.Add(attachment);

            // Enviar el correo
            await smtp.SendMailAsync(mailMessage);
        }
    }
    public async Task EnviarCorreoAsync(string destinatario, string asunto, string mensaje)
    {
        using (var smtp = new SmtpClient())
        {
            smtp.Host = _configuration["Smtp:Host"];
            smtp.Port = int.Parse(_configuration["Smtp:Port"]);
            smtp.Credentials = new NetworkCredential(_configuration["Smtp:User"], _configuration["Smtp:Password"]);
            smtp.EnableSsl = true;

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_configuration["Smtp:User"]),
                Subject = asunto,
                Body = mensaje,
                IsBodyHtml = true
            };

            mailMessage.To.Add(destinatario);
            await smtp.SendMailAsync(mailMessage);
        }
    }
}
