
document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.querySelector("form");
  if (loginForm) {
    loginForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value.trim();

      if (!email || !password) {
        alert("الرجاء إدخال البريد وكلمة المرور");
        return;
      }

      try {
        const response = await fetch("/api/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email, password }),
        });

        const data = await response.json();
        if (response.ok) {
          alert("تم تسجيل الدخول بنجاح");
          // إعادة التوجيه إلى الصفحة الشخصية أو الرئيسية
          window.location.href = "user-profile.html";
        } else {
          alert(data.message || "فشل تسجيل الدخول");
        }
      } catch (error) {
        console.error("Login error:", error);
        alert("حدث خطأ أثناء تسجيل الدخول");
      }
    });
  }
});
