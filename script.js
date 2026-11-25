// Reserved for dashboard interactions. No uploaded file is executed in the browser.
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("file");
  if (input) {
    input.addEventListener("change", () => {
      if (input.files.length) {
        console.info("Selected file:", input.files[0].name);
      }
    });
  }
});
