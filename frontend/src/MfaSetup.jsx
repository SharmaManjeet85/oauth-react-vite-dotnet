import { useState } from "react";
import { setupMfa, verifyMfa } from "./services/mfaService";

export default function MfaSetup() {
  const [qr, setQr] = useState(null);
  const [code, setCode] = useState("");

  const startSetup = async () => {
    const res = await setupMfa();
    setQr(`data:image/png;base64,${res.data.qrCode}`);
  };

  const confirm = async () => {
    await verifyMfa(code);
    alert("MFA Enabled");
  };

  return (
    <div>
      <button onClick={startSetup}>Enable MFA</button>
      {qr && <img src={qr} alt="QR Code" />}
      <input
        placeholder="Enter OTP"
        onChange={e => setCode(e.target.value)}
      />
      <button onClick={confirm}>Verify</button>
    </div>
  );
}