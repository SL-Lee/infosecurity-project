var myChart;

var getData = $.get("/day");

getData.done(function (results) {
  var data = {
    // A labels array that can contain any sort of values
    labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
    // Our series array that contains series objects or in this case series
    // data arrays
    series: [results.low, results.medium, results.high],
  };

  // As options we currently only set a static size of 300x200 px. We can also
  // omit this and use aspect ratio containers as you saw in the previous
  // example
  var options = {
    stackBars: true,
  };

  // Create a new line chart object where as first parameter we pass in a
  // selector that is resolving to our chart container element. The Second
  // parameter is the actual data object. As a third parameter we pass in our
  // custom options.
  myChart = new Chartist.Bar(".ct-chart", data, options).on(
    "draw",
    function (data) {
      if (data.type === "bar") {
        data.element.attr({
          style: "stroke-width: 30px",
        });
      }
    }
  );
});

function updateChartDay() {
  var updatedData = $.get("/day");

  updatedData.done(function (results) {
    var data = {
      // A labels array that can contain any sort of values
      labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      // Our series array that contains series objects or in this case series
      // data arrays
      series: [results.low, results.medium, results.high],
    };
    myChart.update(data);
  });
}
$("#day").on("click", updateChartDay);

function updateChartMonth() {
  var updatedData = $.get("/month");

  updatedData.done(function (results) {
    var data = {
      // A labels array that can contain any sort of values
      labels: results.month,
      // Our series array that contains series objects or in this case series
      // data arrays
      series: [results.low, results.medium, results.high],
    };
    myChart.update(data);
  });
}
$("#month").on("click", updateChartMonth);

function updateChartYear() {
  var updatedData = $.get("/year");

  updatedData.done(function (results) {
    var data = {
      // A labels array that can contain any sort of values
      labels: results.year,
      // Our series array that contains series objects or in this case series
      // data arrays
      series: [results.low, results.medium, results.high],
    };
    myChart.update(data);
  });
}
$("#year").on("click", updateChartYear);
