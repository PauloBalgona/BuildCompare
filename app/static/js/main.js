document.addEventListener("DOMContentLoaded", function () {
  const navLinks = document.querySelectorAll(".bc-navbar .nav-link");

  navLinks.forEach((link) => {
    link.addEventListener("click", function () {
      // Alisin ang active class (at orange underline) sa lahat ng links
      navLinks.forEach((item) => item.classList.remove("active"));
      // Ilagay ang active class sa link na pinindot
      this.classList.add("active");
    });
  });
});