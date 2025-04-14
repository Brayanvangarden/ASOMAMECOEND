namespace Asomameco.Web.Models
{
    public class ErrorMiddlewareViewModel
    {
        public String Path { set; get; } = default!;
        public List<String> ListMessages { set; get; } = default!;
        public String IdEvent { set; get; } = default!;
    }
}
