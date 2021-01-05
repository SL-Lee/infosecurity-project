let contentMinHeight = "100vh - 56px - 16px - 16px - 57px";
let messageContainer = document.getElementById("message-container");

if (messageContainer) {
  contentMinHeight += ` - ${messageContainer.children.length * 66}px`;
}

document.getElementById(
  "content"
).style.minHeight = `calc(${contentMinHeight})`;
