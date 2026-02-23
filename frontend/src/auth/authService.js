import axios from "axios";

const AUTH_API = "http://localhost:5001";

export const login = async (email, password, otp) => {
  const res = await axios.post(`${AUTH_API}/auth/login`, {
    email,
    password,
    otp
  });
  localStorage.setItem("token", res.data.token);
};
export const socialLogin = async (provider) => {
  window.location.href = `${AUTH_API}/auth/social/${provider}`;
};
