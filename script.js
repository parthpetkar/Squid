document.getElementById("portal_form").addEventListener("submit", async function (event) {
    event.preventDefault();
  
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
  
    try {
      const response = await fetch("http://localhost:81/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });
  
      if (response.ok) {
        const data = await response.json(); // Parse JSON response
        console.log(response)
        window.location.href = data.redirectUrl; // Redirect using server-provided URL
      } else {
        const errorMessage = document.getElementById("error-message");
        errorMessage.textContent = "Invalid username or password. Please try again.";
        errorMessage.classList.remove("hidden");
      }
    } catch (error) {
      console.error("Error during login:", error);
    }
  });
  