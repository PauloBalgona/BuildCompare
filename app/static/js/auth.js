document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".bc-toggle-pw").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      const input = document.getElementById(targetId);
      if (!input) return;

      const isPassword = input.type === "password";
      input.type = isPassword ? "text" : "password";
      btn.textContent = isPassword ? "Hide" : "Show";
    });
  });

  const roleCustomer = document.getElementById("roleCustomer");
  const roleOwner = document.getElementById("roleOwner");
  const ownerFields = document.getElementById("ownerFields");

  function syncRoleFields() {
    if (!ownerFields || !roleOwner) return;
    if (roleOwner.checked) {
      ownerFields.classList.remove("d-none");
    } else {
      ownerFields.classList.add("d-none");
    }
  }

  if (roleCustomer && roleOwner) {
    roleCustomer.addEventListener("change", syncRoleFields);
    roleOwner.addEventListener("change", syncRoleFields);
  }
});