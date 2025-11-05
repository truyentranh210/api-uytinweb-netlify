const axios = require("axios");

const GOOGLE_API_KEY = "AIzaSyBk1ABUXXTfzb5JVCk_jSzDUn0GfjMci9I"; // 🔑 Dán Google Safe Browsing API key tại đây
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`;

exports.handler = async (event) => {
  const path = event.path.split("/").pop();
  const params = event.queryStringParameters || {};

  // /home
  if (path === "home") {
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: "👋 Welcome to SafeCheck Lite API",
        usage: {
          home: "/home → Hướng dẫn sử dụng",
          antoan: "/antoan?url=https://example.com → Kiểm tra độ tin cậy website"
        },
        example: "https://yourapp.netlify.app/antoan?url=https://google.com"
      })
    };
  }

  // /antoan
  if (path === "antoan") {
    const url = params.url;
    if (!url) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Thiếu tham số ?url=" })
      };
    }

    try {
      const domain = new URL(url).hostname;

      // 1️⃣ Gọi Google Safe Browsing
      const res = await axios.post(SAFE_BROWSING_URL, {
        client: { clientId: "safecheck", clientVersion: "1.2" },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      });

      const isUnsafe = res.data && res.data.matches && res.data.matches.length > 0;

      // 2️⃣ Phân tích cơ bản
      let trustScore = 100;
      let trustLevel = "Cao";
      let warning = "✅ Trang web an toàn để truy cập.";

      if (!url.startsWith("https://")) trustScore -= 20;

      const suspiciousWords = ["free", "bonus", "login", "giveaway", "xn--", "prize"];
      if (suspiciousWords.some(w => domain.includes(w))) trustScore -= 25;

      if (isUnsafe) {
        trustScore = 10;
        warning = "🚨 Cảnh báo: Trang web có dấu hiệu lừa đảo hoặc chứa mã độc!";
      }

      if (trustScore >= 80) trustLevel = "Cao";
      else if (trustScore >= 50) trustLevel = "Trung bình";
      else trustLevel = "Thấp";

      // 3️⃣ Trả kết quả
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          website: url,
          domain,
          trustScore,
          trustLevel,
          warning,
          checkedAt: new Date().toISOString()
        })
      };
    } catch (e) {
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Không thể kiểm tra URL", details: e.message })
      };
    }
  }

  // Mặc định
  return {
    statusCode: 404,
    body: JSON.stringify({ error: "Không tìm thấy endpoint!" })
  };
};
