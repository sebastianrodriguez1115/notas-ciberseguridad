const unlocked = { hopper: false, psych: false, exit: false };
const STORAGE_KEY = "hopsec_unlocked_v1";
let currentDoor = null;

function saveUnlocked() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(unlocked));
  } catch (e) {}
}
function loadUnlocked() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const data = JSON.parse(raw);
    if (typeof data === "object") {
      if (typeof data.hopper === "boolean") unlocked.hopper = data.hopper;
      if (typeof data.psych === "boolean") unlocked.psych = data.psych;
      if (typeof data.exit === "boolean") unlocked.exit = data.exit;
    }
  } catch (e) {}
}
function applyUnlockedVisuals() {
  Object.keys(unlocked).forEach((d) => {
    if (unlocked[d]) {
      const btn = document.querySelector('.keybtn[data-door="' + d + '"]');
      if (btn) btn.classList.add("unlocked");
    }
  });
  if (unlocked.hopper && unlocked.psych && unlocked.exit) {
    const ed = document.getElementById("escapeDoor");
    if (ed) ed.style.display = "block";
  }
}
function markUnlocked(d) {
  if (!unlocked[d]) {
    unlocked[d] = true;
    const btn = document.querySelector('.keybtn[data-door="' + d + '"]');
    if (btn) btn.classList.add("unlocked");
    saveUnlocked();
    if (unlocked.hopper && unlocked.psych && unlocked.exit) {
      const ed = document.getElementById("escapeDoor");
      if (ed) ed.style.display = "block";
    }
  }
}
function openDoor(door) {
  currentDoor = door;
  const title = document.getElementById("doorTitle");
  const authBlock = document.getElementById("doorAuthBlock");
  const hopperBlock = document.getElementById("hopperBlock");
  const hopperFlag = document.getElementById("hopperFlag");
  const err = document.getElementById("doorError");
  const succ = document.getElementById("doorSuccess");
  const label = document.getElementById("doorSecretLabel");
  const secretInput = document.getElementById("doorSecret");
  err.textContent = "";
  succ.innerHTML = "";
  succ.style.display = "none";
  if (door === "hopper") {
    title.textContent = "EMERGENCY CONTROL: Cell / Storage Wing";
    authBlock.style.display = "none";
    hopperBlock.style.display = "block";
    if (hopperFlag) hopperFlag.style.display = "none";
  } else {
    hopperBlock.style.display = "none";
    authBlock.style.display = "block";
    secretInput.value = "";
    if (door === "psych") {
      title.textContent = "Door Access: Psych Ward Exit";
      label.textContent = "Keycode:";
      secretInput.placeholder = "Enter keycode";
      secretInput.type = "password";
    } else {
      title.textContent = "Door Access: Asylum Exit";
      label.textContent = "SCADA Unlock Passcode:";
      secretInput.placeholder = "Enter passcode";
      secretInput.type = "password";
    }
  }
  document.getElementById("modalBg").style.display = "flex";
}
function closeModal() {
  document.getElementById("modalBg").style.display = "none";
}
async function unlockCell() {
  const flagDiv = document.getElementById("hopperFlag");
  const span = document.getElementById("hopperFlagText");
  if (flagDiv) flagDiv.style.display = "none";
  try {
    const res = await fetch("/cgi-bin/key_flag.sh?door=hopper");
    const data = await res.json();
    if (data && data.ok && data.flag) {
      if (span) span.textContent = data.flag;
      if (flagDiv) flagDiv.style.display = "block";
      markUnlocked("hopper");
    } else {
      if (flagDiv) {
        flagDiv.style.display = "block";
        flagDiv.innerHTML =
          "<div>Unlock succeeded, but flag could not be retrieved.</div>";
      }
      markUnlocked("hopper");
    }
  } catch (e) {
    if (flagDiv) {
      flagDiv.style.display = "block";
      flagDiv.innerHTML = "<div>Error contacting server for flag.</div>";
    }
  }
}
async function submitDoorSecret() {
  if (currentDoor !== "psych" && currentDoor !== "exit") return;
  const secret = document.getElementById("doorSecret").value.trim();
  const e = document.getElementById("doorError");
  const s = document.getElementById("doorSuccess");
  e.textContent = "";
  s.innerHTML = "";
  s.style.display = "none";
  if (!secret) {
    e.textContent = "Please enter a code.";
    return;
  }
  const endpoint =
    currentDoor === "psych"
      ? "/cgi-bin/psych_check.sh"
      : "/cgi-bin/exit_check.sh";
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "code=" + encodeURIComponent(secret),
    });
    const data = await res.json();
    if (data && data.error === "rate_limit") {
      e.textContent = "Too many attempts. Please wait and try again.";
      return;
    }
    if (!data || !data.ok) {
      e.textContent = "Invalid code.";
      return;
    }
    const flag = data.flag || "";
    let html = "";
    if (currentDoor === "psych") {
      html += "<div><strong>Psych Ward exit keycode accepted.</strong></div>";
      html +=
        '<p style="margin:6px 0 4px;font-size:12px;">This is only the first part of your second flag. You will need to complete it elsewhere.</p>';
      if (flag) {
        html +=
          '<div class="flag-row"><span class="flag" id="psychFlagText"></span><button class="copybtn" onclick="copyById(\'psychFlagText\')">Copy</button></div>';
      }
      markUnlocked("psych");
    } else {
      html +=
        "<div><strong>Asylum Exit SCADA passcode accepted.</strong></div>";
      if (flag) {
        html +=
          '<div class="flag-row"><span class="flag" id="exitFlagText"></span><button class="copybtn" onclick="copyById(\'exitFlagText\')">Copy</button></div>';
      }
      markUnlocked("exit");
    }
    s.innerHTML = html;
    s.style.display = "block";
    if (currentDoor === "psych" && flag) {
      const span = document.getElementById("psychFlagText");
      if (span) span.textContent = flag;
    }
    if (currentDoor === "exit" && flag) {
      const span = document.getElementById("exitFlagText");
      if (span) span.textContent = flag;
    }
  } catch (err) {
    e.textContent = "Error contacting server.";
  }
}
function viewCamera(id) {
  alert("Camera " + id + " feed is currently unavailable.");
}
function copyById(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const txt = el.textContent.trim();
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).catch(() => {});
  } else {
    const ta = document.createElement("textarea");
    ta.value = txt;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
    } catch (e) {}
    document.body.removeChild(ta);
  }
}
function showEscapeModal() {
  const modal = document.getElementById("escapeModal");
  const err = document.getElementById("escapeError");
  const res = document.getElementById("escapeResult");
  const f1 = document.getElementById("flag1Input");
  const f2 = document.getElementById("flag2Input");
  const f3 = document.getElementById("flag3Input");
  if (f1) f1.value = "";
  if (f2) f2.value = "";
  if (f3) f3.value = "";
  err.textContent = "";
  res.innerHTML = "";
  res.style.display = "none";
  modal.style.display = "flex";
}
function closeEscapeModal() {
  document.getElementById("escapeModal").style.display = "none";
}
async function submitEscapeFlags() {
  const f1 = document.getElementById("flag1Input").value.trim();
  const f2 = document.getElementById("flag2Input").value.trim();
  const f3 = document.getElementById("flag3Input").value.trim();
  const err = document.getElementById("escapeError");
  const res = document.getElementById("escapeResult");
  err.textContent = "";
  res.innerHTML = "";
  res.style.display = "none";
  if (!f1 || !f2 || !f3) {
    err.textContent = "Please enter all three flags.";
    return;
  }
  try {
    const resp = await fetch("/cgi-bin/escape_check.sh", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:
        "flag1=" +
        encodeURIComponent(f1) +
        "&flag2=" +
        encodeURIComponent(f2) +
        "&flag3=" +
        encodeURIComponent(f3),
    });
    const data = await resp.json();
    if (!data || !data.ok) {
      err.textContent = "One or more flags are incorrect.";
      return;
    }
    const url = data.invite_url || "";
    const code = data.invite_code || "";
    let html =
      "<p>All three flags verified. Hopper grants you access to his next challenge.</p>";
    if (url) {
      html +=
        '<div class="flag-row"><span class="flag" id="escapeUrl"></span><button class="copybtn" onclick="copyById(\'escapeUrl\')">Copy URL</button></div>';
    }
    if (code) {
      html +=
        '<div class="flag-row"><span class="flag" id="escapeCode"></span><button class="copybtn" onclick="copyById(\'escapeCode\')">Copy invite code</button></div>';
    }
    res.innerHTML = html;
    res.style.display = "block";
    if (url) {
      const su = document.getElementById("escapeUrl");
      if (su) su.textContent = url;
    }
    if (code) {
      const sc = document.getElementById("escapeCode");
      if (sc) sc.textContent = code;
    }
  } catch (e) {
    err.textContent = "Error contacting server.";
  }
}
async function checkSession() {
  const loginWin = document.getElementById("loginWindow");
  const map = document.getElementById("mapScreen");
  try {
    const res = await fetch("/cgi-bin/session_check.sh", { cache: "no-store" });
    const data = await res.json();
    if (data && data.authed) {
      loginWin.style.display = "none";
      map.style.display = "block";
    } else {
      loginWin.style.display = "block";
      map.style.display = "none";
    }
  } catch (e) {
    loginWin.style.display = "block";
    map.style.display = "none";
  }
}
document.addEventListener("DOMContentLoaded", async function () {
  await checkSession();
  loadUnlocked();
  applyUnlockedVisuals();
});
