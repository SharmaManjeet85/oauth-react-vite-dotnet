import api from "./apiClient";

export const setupMfa = async () => {
  return api.post("/auth/mfa/setup");
};

export const verifyMfa = async (code) => {
  return api.post("/auth/mfa/verify", { code });
};