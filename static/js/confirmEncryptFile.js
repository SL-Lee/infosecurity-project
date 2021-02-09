function confirmUpload() {
  var message = confirm("Are you sure you want to encrypt this file?")
    ? "You pressed OK!"
    : "You pressed cancel!";
  document.querySelector("form").onclick = function () {
    location.href = "download-file.html";
  };
}

function confirmUpload2() {
  var message = confirm("Are you sure you want to decrypt this file?")
    ? "You pressed OK!"
    : "You pressed cancel!";
  document.querySelector("form").onclick = function () {
    location.href = "download-file2.html";
  };
}
