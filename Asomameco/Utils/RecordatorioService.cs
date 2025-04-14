using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Asomameco.Infraestructure.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

public class RecordatorioService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly EmailService _emailService;

    public RecordatorioService(IServiceProvider serviceProvider, EmailService emailService)
    {
        _serviceProvider = serviceProvider;
        _emailService = emailService;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<AsomamecoContext>();
                var manana = DateTime.Today.AddDays(1);

                var usuarios = context.Usuario
                    .Where(u => u.Estado2 == 1)
                    .ToList();

                //En Construccion
                /*
                foreach (var usuario in usuarios)
                {
                    await _emailService.EnviarCorreoAsync(usuario.Correo, "Recordatorio de Asamblea",
                        "Recuerda que la asamblea es mañana. Presenta tu código QR.");
                }
                */
            }

            // Ejecutar cada 24 horas
            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }
}
