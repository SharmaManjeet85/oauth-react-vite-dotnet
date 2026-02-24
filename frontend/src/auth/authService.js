import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5001",
  withCredentials: false
});

export const login = async (email, password, otp) => {
  const res = await api.post("/auth/login", {
    email,
    password,
    otp
  });
  localStorage.setItem("token", res.data.token);
};

export const verifyMfa = async (code) => {
  const token = localStorage.getItem("token");

  return api.post(
    "/auth/mfa/verify",
    { code },
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );
};
export const socialLogin = async (provider) => {
  const res = await api.get(`/auth/social/${provider}`);
  window.location.href = res.data.url;
}