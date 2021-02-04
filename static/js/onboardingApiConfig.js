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
          $("#open-api-key-generation-prompt-btn").attr("disabled", "");
        },
        error => {
          $(".modal").modal("hide");
          $("#api-key-generation-failure-modal").modal();
        },
      );
  });
