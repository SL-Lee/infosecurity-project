function restore(file, time) {
  if (confirm("Are you sure you want to restore file back to time?")) {
    location.href = "/backup/" + (file) + "/" + (time) + "/restore";
  }
}

var current = 0;
var first = 0;
var last = 10;
function nextPage() {
  // numbers are following index
  var i, tbody, tr;
  tbody = document.getElementsByTagName("tbody")[0];
  tr = tbody.getElementsByTagName("tr");

  // set all to hidden first
  for (i = 0; i < pages * 10; i++) {
    if (tr[i]) {
      tr[i].style.display = "none";
    }
  }

  current += 1;
  first += 10;
  last += 10;

  for (i = first; i < last; i++) {
    if (tr[i]) {
      tr[i].style.display = "";
    }
  }

  if (current + 1 == 1) {
    var previous = document.getElementById("previous");
    previous.classList.add("disabled");
    previous.firstChild.tabIndex = "-1";
  } else {
    var previous = document.getElementById("previous");
    previous.classList.remove("disabled");
    previous.firstChild.tabIndex = "";
  }

  if (current + 1 < pages) {
    var next = document.getElementById("next");
    next.classList.remove("disabled");
    next.firstChild.tabIndex = "";
  } else {
    var next = document.getElementById("next");
    next.classList.add("disabled");
    next.firstChild.tabIndex = "-1";
  }
}

function previousPage() {
  // numbers are following index
  var i, tbody, tr;
  tbody = document.getElementsByTagName("tbody")[0];
  tr = tbody.getElementsByTagName("tr");

  // set all to hidden first
  for (i = 0; i < pages * 10; i++) {
    if (tr[i]) {
      tr[i].style.display = "none";
    }
  }

  current -= 1;
  first -= 10;
  last -= 10;

  for (i = first; i < last; i++) {
    if (tr[i]) {
      tr[i].style.display = "";
    }
  }

  if (current + 1 == 1) {
    var previous = document.getElementById("previous");
    previous.classList.add("disabled");
    previous.firstChild.tabIndex = "-1";
  } else {
    var previous = document.getElementById("previous");
    previous.classList.remove("disabled");
    previous.firstChild.tabIndex = "";
  }

  if (current + 1 < pages) {
    var next = document.getElementById("next");
    next.classList.remove("disabled");
    next.firstChild.tabIndex = "";
  } else {
    var next = document.getElementById("next");
    next.classList.add("disabled");
    next.firstChild.tabIndex = "-1";
  }
}

function goToPage(page) {
  // numbers are following index
  var i, tbody, tr;
  tbody = document.getElementsByTagName("tbody")[0];
  tr = tbody.getElementsByTagName("tr");

  // set all to hidden first
  for (i = 0; i < pages * 10; i++) {
    if (tr[i]) {
      tr[i].style.display = "none";
    }
  }

  current = page - 1;
  first = page * 10 - 10;
  last = page * 10;

  for (i = first; i < last; i++) {
    if (tr[i]) {
      tr[i].style.display = "";
    }
  }

  if (current + 1 == 1) {
    var previous = document.getElementById("previous");
    previous.classList.add("disabled");
    previous.firstChild.tabIndex = "-1";
  } else {
    var previous = document.getElementById("previous");
    previous.classList.remove("disabled");
    previous.firstChild.tabIndex = "";
  }

  if (current + 1 < pages) {
    var next = document.getElementById("next");
    next.classList.remove("disabled");
    next.firstChild.tabIndex = "";
  } else {
    var next = document.getElementById("next");
    next.classList.add("disabled");
    next.firstChild.tabIndex = "-1";
  }
}
