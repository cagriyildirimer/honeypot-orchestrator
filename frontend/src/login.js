// Dynamic status messages for the cybersecurity boot-up sequence
const loaderStages = [
  { percent: 0, text: "Initializing secure operations console..." },
  { percent: 22, text: "Loading cryptographic modules..." },
  { percent: 50, text: "Establishing secure protocol handshake..." },
  { percent: 76, text: "Syncing decoy system registries..." },
  { percent: 94, text: "Ready. Launching control room..." }
];

function runSplashSequence(onComplete) {
  const splash = document.querySelector("#splashScreen");
  const shell = document.querySelector("#loginShell");
  const progress = document.querySelector(".splash-loader-progress");
  const status = document.querySelector(".splash-status");

  if (!splash || !shell || !progress) {
    if (onComplete) onComplete();
    return;
  }

  let currentPercent = 0;
  const duration = 1800; // 1.8 seconds total boot-up time
  const intervalTime = 20; // 20ms steps
  const totalSteps = duration / intervalTime;
  const stepIncrement = 100 / totalSteps;

  const interval = setInterval(() => {
    currentPercent += stepIncrement;
    if (currentPercent >= 100) {
      currentPercent = 100;
      clearInterval(interval);
      completeSplash();
    }

    // Update progress bar width
    progress.style.width = `${currentPercent}%`;

    // Update status text based on current percentage
    const stage = loaderStages.reduce((prev, curr) => {
      return (currentPercent >= curr.percent) ? curr : prev;
    }, loaderStages[0]);
    
    if (status && status.textContent !== stage.text) {
      status.textContent = stage.text;
    }
  }, intervalTime);

  function completeSplash() {
    clearInterval(interval);
    
    // Fade out splash screen (triggers CSS transition)
    splash.classList.add("fade-out");
    
    // Smoothly reveal login card (already rendered, triggers opacity/transform fade-in)
    shell.classList.add("fade-in-active");
    
    if (onComplete) onComplete();

    // Completely remove splash from DOM after transition completes to save resources
    setTimeout(() => {
      splash.remove();
    }, 700);
  }
}

function showLoginError(message) {
  const node = document.querySelector("#loginError");
  if (!node) {
    return;
  }
  node.hidden = !message;
  node.textContent = message || "";
}

async function submitLogin(event) {
  event.preventDefault();
  const button = document.querySelector("#loginButton");
  const usernameInput = document.querySelector("#usernameInput");
  const passwordInput = document.querySelector("#passwordInput");
  if (!button || !usernameInput || !passwordInput) {
    return;
  }
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  button.disabled = true;
  showLoginError("");

  try {
    const session = await requestJson("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    window.location.assign("/dashboard");
  } catch (error) {
    showLoginError(error.message);
  } finally {
    button.disabled = false;
  }
}

async function bootstrapLogin() {
  const loginForm = document.querySelector("#loginForm");
  if (!loginForm) {
    return;
  }
  loginForm.addEventListener("submit", submitLogin);

  // Bind password visibility toggle
  const togglePasswordBtn = document.querySelector("#togglePasswordBtn");
  const passwordInput = document.querySelector("#passwordInput");
  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener("click", () => {
      const isPassword = passwordInput.type === "password";
      passwordInput.type = isPassword ? "text" : "password";
      
      // Visual feedback: toggle class to highlight the eye button when visible
      togglePasswordBtn.classList.toggle("visible", !isPassword);
    });
  }

  // Check if session is already authenticated
  try {
    const session = await requestJson("/api/session");
    if (session.authenticated) {
      window.location.replace("/dashboard");
      return; // Skip splash and redirect
    }
  } catch (error) {
    // Not authenticated, continue to splash and login card
  }

  // If not authenticated, play the beautiful splash boot-up sequence
  runSplashSequence(() => {
    const usernameInput = document.querySelector("#usernameInput");
    if (usernameInput) {
      usernameInput.focus();
    }
  });
}

bootstrapLogin();
