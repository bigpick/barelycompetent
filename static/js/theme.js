const theme = window.localStorage && window.localStorage.getItem("theme");
const themeToggle = document.querySelector(".theme-toggle");
const isDark = theme === "dark";
var metaThemeColor = document.querySelector("meta[name=theme-color]");

if (theme !== null) {
  document.body.classList.toggle("dark-theme", isDark);
  isDark
    ? metaThemeColor.setAttribute("content", "#282a36")
    : metaThemeColor.setAttribute("content", "#f8f8f2");
}

themeToggle.addEventListener("click", () => {
  document.body.classList.toggle("dark-theme");
  window.localStorage &&
    window.localStorage.setItem(
      "theme",
      document.body.classList.contains("dark-theme") ? "dark" : "light"
    );
  document.body.classList.contains("dark-theme")
    ? metaThemeColor.setAttribute("content", "#282a36")
    : metaThemeColor.setAttribute("content", "#f8f8f2")+console.log("Dracula hates the light!!!")
});
