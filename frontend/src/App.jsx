import { useState } from "react";
import { login, socialLogin } from "./auth/authService";

function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");

const handleLogin = async () => {
  await login(email, password, otp);
};

  return (
    <div>
      <h2>Login</h2>
      <input placeholder="Email" onChange={e => setEmail(e.target.value)} />
      <input type="password" placeholder="Password" onChange={e => setPassword(e.target.value)} />
      <input placeholder="OTP (if enabled)" onChange={e => setOtp(e.target.value)} />

      <button onClick={handleLogin}>Login</button>

      <hr />

      <button onClick={() => socialLogin("google")}>Google</button>
      <button onClick={() => socialLogin("github")}>GitHub</button>
    </div>
  );
}

export default App;
