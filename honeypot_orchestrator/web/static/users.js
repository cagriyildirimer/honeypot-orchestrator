const usersState = {
  username: "",
  role: "",
  users: [],
  mode: "idle",
  activeUser: "",
};

const ROLE_LABELS = {
  admin: "Full access",
  viewer: "Log viewer",
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

function createRoleSelect(id, selectedRole) {
  const select = document.createElement("select");
  select.id = id;
  for (const role of ["admin", "viewer"]) {
    const option = document.createElement("option");
    option.value = role;
    option.textContent = ROLE_LABELS[role];
    option.selected = role === selectedRole;
    select.appendChild(option);
  }
  return select;
}

function renderUsers() {
  const table = document.querySelector("#usersTable");
  if (!table) {
    return;
  }
  table.innerHTML = "";

  if (usersState.role !== "admin") {
    const row = document.createElement("tr");
    const cell = createCell("Admin access required.");
    cell.colSpan = 4;
    cell.className = "empty-row";
    row.appendChild(cell);
    table.appendChild(row);
    return;
  }

  for (const user of usersState.users) {
    if (usersState.mode === "password" && usersState.activeUser === user.username) {
      renderPasswordRow(table, user);
      continue;
    }
    if (usersState.mode === "role" && usersState.activeUser === user.username) {
      renderRoleRow(table, user);
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

    const passwordCell = document.createElement("td");
    const changePasswordButton = document.createElement("button");
    changePasswordButton.type = "button";
    changePasswordButton.className = "button secondary";
    changePasswordButton.textContent = "Change Password";
    changePasswordButton.addEventListener("click", () => {
      usersState.mode = "password";
      usersState.activeUser = user.username;
      renderUsers();
    });
    passwordCell.appendChild(changePasswordButton);

    const roleCell = document.createElement("td");
    const roleButton = document.createElement("button");
    roleButton.type = "button";
    roleButton.className = "button secondary";
    roleButton.textContent = ROLE_LABELS[user.role] || ROLE_LABELS.viewer;
    roleButton.addEventListener("click", () => {
      usersState.mode = "role";
      usersState.activeUser = user.username;
      renderUsers();
    });
    roleCell.appendChild(roleButton);

    const deleteCell = document.createElement("td");
    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "button danger";
    deleteButton.textContent = "Delete";
    deleteButton.disabled = user.username === usersState.username;
    deleteButton.title = deleteButton.disabled ? "You cannot delete the signed-in user." : "";
    deleteButton.addEventListener("click", () => deleteUser(user.username));
    deleteCell.appendChild(deleteButton);

    row.append(usernameCell, passwordCell, roleCell, deleteCell);
    table.appendChild(row);
  }

  if (usersState.mode === "create") {
    renderCreateRow(table);
    return;
  }

  const addRow = document.createElement("tr");
  addRow.className = "add-user-row";
  const addCell = document.createElement("td");
  addCell.colSpan = 4;
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

function renderPasswordRow(table, user) {
  const row = document.createElement("tr");
  row.className = "inline-form-row";
  const usernameCell = createCell(user.username);
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
  form.addEventListener("submit", (event) => changePassword(event, user.username, passwordInput));
  formCell.appendChild(form);
  row.append(usernameCell, formCell, createCell(ROLE_LABELS[user.role] || ROLE_LABELS.viewer), createCell(""));
  table.appendChild(row);
  passwordInput.focus();
}

function renderRoleRow(table, user) {
  const row = document.createElement("tr");
  row.className = "inline-form-row";
  const usernameCell = createCell(user.username);
  const passwordCell = createCell("Password unchanged");
  const roleCell = document.createElement("td");
  const form = document.createElement("form");
  form.className = "table-inline-form role-inline-form";
  const roleSelect = createRoleSelect("changedRole", user.role || "viewer");
  const saveButton = document.createElement("button");
  saveButton.type = "submit";
  saveButton.className = "button";
  saveButton.textContent = "Save";
  const cancelButton = document.createElement("button");
  cancelButton.type = "button";
  cancelButton.className = "button secondary";
  cancelButton.textContent = "Cancel";
  cancelButton.addEventListener("click", closeInlineForm);
  form.append(roleSelect, saveButton, cancelButton);
  form.addEventListener("submit", (event) => changeRole(event, user.username, roleSelect));
  roleCell.appendChild(form);
  row.append(usernameCell, passwordCell, roleCell, createCell(""));
  table.appendChild(row);
  roleSelect.focus();
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

  const passwordCell = document.createElement("td");
  const passwordInput = createPasswordInput("newPassword");
  passwordInput.setAttribute("form", "createUserInlineForm");
  passwordCell.appendChild(passwordInput);

  const roleCell = document.createElement("td");
  const form = document.createElement("form");
  form.id = "createUserInlineForm";
  form.className = "table-inline-form role-inline-form";
  const roleSelect = createRoleSelect("newRole", "viewer");
  const createButton = document.createElement("button");
  createButton.type = "submit";
  createButton.className = "button";
  createButton.textContent = "Create";
  const cancelButton = document.createElement("button");
  cancelButton.type = "button";
  cancelButton.className = "button secondary";
  cancelButton.textContent = "Cancel";
  cancelButton.addEventListener("click", closeInlineForm);
  form.append(roleSelect, createButton, cancelButton);
  form.addEventListener("submit", (event) => createUser(event, usernameInput, passwordInput, roleSelect));
  roleCell.appendChild(form);
  row.append(userCell, passwordCell, roleCell, createCell(""));
  table.appendChild(row);
  usernameInput.focus();
}

function closeInlineForm() {
  usersState.mode = "idle";
  usersState.activeUser = "";
  renderUsers();
}

async function refreshUsers() {
  const session = await requestJson("/api/session");
  usersState.username = session.username || "";
  usersState.role = session.role || "";
  setText("#sessionUser", usersState.username || "-");

  if (usersState.role !== "admin") {
    usersState.users = [];
    renderUsers();
    return;
  }

  const payload = await requestJson("/api/users");
  usersState.users = payload.users || [];
  renderUsers();
}

async function createUser(event, usernameInput, passwordInput, roleSelect) {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  const role = roleSelect.value;
  try {
    await requestJson("/api/users", {
      method: "POST",
      body: JSON.stringify({ username, password, role }),
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

async function changeRole(event, username, roleSelect) {
  event.preventDefault();
  try {
    await requestJson("/api/users/role", {
      method: "POST",
      body: JSON.stringify({ username, role: roleSelect.value }),
    });
    usersState.mode = "idle";
    usersState.activeUser = "";
    await refreshUsers();
    showToast(`Role updated for ${username}.`, "success");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function deleteUser(username) {
  if (!username) {
    return;
  }
  try {
    await requestJson("/api/users/delete", {
      method: "POST",
      body: JSON.stringify({ username }),
    });
    await refreshUsers();
    showToast(`User ${username} deleted.`, "success");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function bootstrapUsers() {
  document.querySelector("#logoutButton")?.addEventListener("click", logoutAndRedirect);
  try {
    const session = await ensureAuthenticated();
    usersState.username = session.username || "";
    usersState.role = session.role || "";
    await refreshUsers();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapUsers();
