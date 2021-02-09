let docLinks = document.querySelectorAll(".doc-link");

document.getElementById("visible-doc-links-count").innerText = docLinks.length;
document.getElementById("total-doc-links-count").innerText = docLinks.length;

document
  .getElementById("doc-search-input")
  .addEventListener("keyup", function (e) {
    let currentSearchTerm = this.value.toLowerCase();
    let visibleDocLinksCount = docLinks.length;
    docLinks.forEach((docLink) => {
      if (docLink.textContent.toLowerCase().includes(currentSearchTerm)) {
        docLink.style.display = "block";
      } else {
        docLink.style.display = "none";
        visibleDocLinksCount -= 1;
      }

      document.getElementById(
        "visible-doc-links-count"
      ).innerText = visibleDocLinksCount;
    });
  });
