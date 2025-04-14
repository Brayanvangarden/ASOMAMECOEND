$(document).ready(function () {
    $(".service-card").hover(
        function () {
            $(this).css("background", "#f8f9fa");
            $(this).find(".card-text").append("<small class='text-muted d-block mt-2'>Más información aquí...</small>");
        },
        function () {
            $(this).css("background", "#fff");
            $(this).find(".text-muted").remove();
        }
    );
});
