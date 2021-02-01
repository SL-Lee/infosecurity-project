// Pass server user ID to modal when they are shown
window.addEventListener("load", _ => {
  $("#delete-user-alert").on("show.bs.modal", function (e) {
    document.getElementById(
      "server-user-id"
    ).value = e.relatedTarget.getAttribute("data-server-user-id");
  });
});
