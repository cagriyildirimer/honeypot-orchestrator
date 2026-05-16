const usersState = {
  username: "",
  users: [],
  mode: "idle",
  activeUser: "",
};

function createCell(textContent) {
  const cell = document.createElement("td");
  cell.textContent = textContent;
  return cell;
}

function createPasswordInput(id) {
  const input = document.createElement("input");
  input.id = id;
  input.type = "password";
  input.autocomplete = "new-password";
  input.required = true;
  input.placeholder = "New password";
  return input;
}

function renderUsers() {
  const table = document.querySelector("#usersTable");
  if (!table) {
    return;
  }
  table.innerHTML = "";

  for (const user of usersState.users) {
    if (usersState.mode === "password" && usersState.activeUser === user.username) {
      renderPasswordRow(table, user.username);
      continue;
    }

    const row = document.createElement("tr");
    const usernameCell = document.createElement("td");
    usernameCell.className = "user-name-cell";
    const usernameText = document.createElement("span");
    usernameText.textContent = text(user.username);
    usernameCell.appendChild(usernameText);
    if (user.username === usersState.username) {
      const currentMarker = document.createElement("span");
      currentMarker.className = "current-user-marker";
      currentMarker.setAttribute("aria-label", "Current user");
      usernameCell.appendChild(currentMarker);
    }
    const actionCell = document.createElement("td");
    const changeButton = document.createElement("button");
    changeButton.type = "button";
    changeButton.className = "button secondary";
    changeButton.textContent = "Change Password";
    changeButton.addEventListener("click", () => {
      usersState.mode = "password";
      usersState.activeUser = user.username;
      renderUsers();
    });
    actionCell.appendChild(changeButton);
    row.append(usernameCell, actionCell);
    table.appendChild(row);
  }

  if (usersState.mode === "create") {
    renderCreateRow(table);
    return;
  }

  const addRow = document.createElement("tr");
  addRow.className = "add-user-row";
  const addCell = document.createElement("td");
  addCell.colSpan = 2;
  const addButton = document.createElement("button");
  addButton.type = "button";
  addButton.className = "button secondary icon-button";
  addButton.textContent = "+";
  addButton.setAttribute("aria-label", "Create user");
  addButton.addEventListener("click", () => {
    usersState.mode = "create";
    usersState.activeUser = "";
    renderUsers();
  });
  addCell.appendChild(addButton);
  addRow.appendChild(addCell);
  table.appendChild(addRow);
}

function renderPasswordRow(table, username) {
  const row = document.createElement("tr");
  row.className = "inline-form-row";
  const usernameCell = createCell(username);
  const formCell = document.createElement("td");
  const form = document.createElement("form");
  form.className = "table-inline-form";
  const passwordInput = createPasswordInput("changedPassword");
  const saveButton = document.createElement("button");
  saveButton.type = "submit";
  saveButton.className = "button";
  saveButton.textContent = "Save";
  const cancelButton = document.createElement("button");
  cancelButton.type = "button";
  cancelButton.className = "button secondary";
  cancelButton.textContent = "Cancel";
  cancelButton.addEventListener("click", closeInlineForm);
  form.append(passwordInput, saveButton, cancelButton);
  form.addEventListener("submit", (event) => changePassword(event, username, passwordInput));
  formCell.appendChild(form);
  row.append(usernameCell, formCell);
  table.appendChild(row);
  passwordInput.focus();
}

function renderCreateRow(table) {
  const row = document.createElement("tr");
  row.className = "inline-form-row";
  const userCell = document.createElement("td");
  const usernameInput = document.createElement("input");
  usernameInput.setAttribute("form", "createUserInlineForm");
  usernameInput.id = "newUsername";
  usernameInput.type = "text";
  usernameInput.autocomplete = "off";
  usernameInput.required = true;
  usernameInput.placeholder = "Username";
  userCell.appendChild(usernameInput);

  const formCell = document.createElement("td");
  const form = document.createElement("form");
  form.id = "createUserInlineForm";
  form.className = "table-inline-form";
  const passwordInput = createPasswordInput("newPassword");
  const createButton = document.createElement("button");
  createButton.type = "submit";
  createButton.className = "button";
  createButton.textContent = "Create";
  const cancelButton = document.createElement("button");
  cancelButton.type = "button";
  cancelButton.className = "button secondary";
  cancelButton.textContent = "Cancel";
  cancelButton.addEventListener("click", closeInlineForm);
  form.append(passwordInput, createButton, cancelButton);
  form.addEventListener("submit", (event) => createUser(event, usernameInput, passwordInput));
  formCell.appendChild(form);
  row.append(userCell, formCell);
  table.appendChild(row);
  usernameInput.focus();
}

function closeInlineForm() {
  usersState.mode = "idle";
  usersState.activeUser = "";
  renderUsers();
}

async function refreshUsers() {
  const payload = await requestJson("/api/settings");
  usersState.username = payload.session ? payload.session.username : usersState.username;
  usersState.users = payload.users || [];
  setText("#sessionUser", usersState.username || "-");
  renderUsers();
}

async function createUser(event, usernameInput, passwordInput) {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  try {
    await requestJson("/api/users", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    usersState.mode = "idle";
    await refreshUsers();
    showToast(`User ${username} created.`, "success");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function changePassword(event, username, passwordInput) {
  event.preventDefault();
  try {
    await requestJson("/api/users/password", {
      method: "POST",
      body: JSON.stringify({ username, password: passwordInput.value }),
    });
    usersState.mode = "idle";
    usersState.activeUser = "";
    await refreshUsers();
    showToast(`Password updated for ${username}.`, "success");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function bootstrapUsers() {
  document.querySelector("#logoutButton")?.addEventListener("click", logoutAndRedirect);
  try {
    const session = await ensureAuthenticated();
    usersState.username = session.username || "";
    await refreshUsers();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapUsers();
