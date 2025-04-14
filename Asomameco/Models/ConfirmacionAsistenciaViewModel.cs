namespace Asomameco.Web.Models
{
    public class ConfirmacionAsistenciaViewModel
    {
        public int IdMiembro { get; set; }
        public string Nombre { get; set; }
        public int IdAsamblea { get; set; }
        public DateTime FechaAsamblea { get; set; }
        public DateTime FechaConfirmacion { get; set; }
    }
}
