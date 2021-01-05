// Event handler for submitting the generate new API key form
document
  .getElementById("generate-new-api-key-form")
  .addEventListener("submit", function (e) {
    e.preventDefault();
    fetch("/api/key-management/generate", {
      "method": "POST",
      "headers": { "X-CSRFToken": csrfToken },
      "body": new FormData(this),
    })
      .then(response => {
        return response.ok
          ? response.json()
          : Promise.reject("Error while generating API key");
      })
      .then(
        json => {
          $(".modal").modal("hide");
          $("#generated-api-key-name").text(json["new-api-key-name"]);
          $("#new-api-key").text(json["new-api-key"]);
          $("#api-key-generation-success-modal").modal();
          $("#api-key-generation-success-modal").on("hidden.bs.modal", e => {
            location.reload();
          });
        },
        error => {
          $(".modal").modal("hide");
          $("#api-key-generation-failure-modal").modal();
        },
      );
  });

// Pass index of API key to modal when they are shown
window.addEventListener("load", _ => {
  $("#rename-api-key-prompt").on("show.bs.modal", e => {
    document.getElementById(
      "rename-api-key-index"
    ).value = e.relatedTarget.getAttribute("data-api-key-index");
  });

  $("#revoke-api-key-alert").on("show.bs.modal", function (e) {
    document.getElementById(
      "revoke-api-key-index"
    ).value = e.relatedTarget.getAttribute("data-api-key-index");
  });
});
