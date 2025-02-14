const form = document.querySelector(".otp-form");
const inputs = [...form.querySelectorAll("input[type=text]")];
const submit = form.querySelector("button[type=submit]");

const handleKeyDown = (e) => {
  if (
    !/^[0-9]{1}$/.test(e.key) &&
    e.key !== "Backspace" &&
    e.key !== "Delete" &&
    e.key !== "Tab" &&
    !e.metaKey
  ) {
    e.preventDefault();
  }

  if (e.key === "Delete" || e.key === "Backspace") {
    const index = inputs.indexOf(e.target);
    if (index > 0) {
      inputs[index - 1].value = "";
      inputs[index - 1].focus();
    }
  }
};

const handleInput = (e) => {
  const { target } = e;
  const index = inputs.indexOf(target);

  if (index < 3) {
    if (target.value) {
      if (index < inputs.length - 1) {
        inputs[index + 1].focus();
      } else {
        submit.focus();
      }
    }
  }
};

const handleFocus = (e) => {
  e.target.select();
};

const handlePaste = (e) => {
  e.preventDefault();
  const text = e.clipboardData.getData("text");
  if (!new RegExp(`^[0-9]{${inputs.length}}$`).test(text)) {
    return;
  }
  const digits = text.split("");
  inputs.forEach((input, index) => (input.value = digits[index]));
  submit.focus();
};

inputs.forEach((input) => {
  input.addEventListener("input", handleInput);
  input.addEventListener("keydown", handleKeyDown);
  input.addEventListener("focus", handleFocus);
  input.addEventListener("paste", handlePaste);
});
