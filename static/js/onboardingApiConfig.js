document
  .getElementById("generate-new-api-key-form")
  .addEventListener("submit", function (e) {
    e.preventDefault();
    fetch(apiKeyGenerateRoute, {
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
