const axios = require("axios");
const whois = require("whois-json");

const GOOGLE_API_KEY = "AIzaSyBk1ABUXXTfzb5JVCk_jSzDUn0GfjMci9I"; // 🔑 Dán Google Safe Browsing API key tại đây
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`;

exports.handler = async (event) => {
  const path = event.path.split("/").pop();
  const params = event.queryStringParameters || {};

  // ====== /home ======
  if (path === "home") {
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: "👋 Welcome to SafeCheck Pro API",
        usage: {
          home: "/home → Hiển thị hướng dẫn sử dụng",
          antoan: "/antoan?url=https://example.com → Kiểm tra độ tin cậy website"
        },
        example: "https://yourapp.netlify.app/antoan?url=https://google.com"
      })
    };
  }

  // ====== /antoan ======
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

      // 1️⃣ Gọi Google Safe Browsing API
      const res = await axios.post(SAFE_BROWSING_URL, {
        client: { clientId: "safecheck", clientVersion: "1.1" },
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

      // 2️⃣ Lấy thông tin WHOIS (để tính tuổi domain)
      let domainAgeYears = 0;
      try {
        const info = await whois(domain);
        if (info.creationDate) {
          const create = new Date(info.creationDate);
          const now = new Date();
          domainAgeYears = Math.floor((now - create) / (365 * 24 * 60 * 60 * 1000));
        }
      } catch {
        domainAgeYears = 0;
      }

      // 3️⃣ Tính điểm tin cậy
      let trustScore = 100;
      let trustLevel = "Cao";
      let warning = "✅ Trang web an toàn để truy cập.";

      // Giảm điểm nếu không HTTPS
      if (!url.startsWith("https://")) trustScore -= 15;

      // Giảm điểm nếu domain mới
      if (domainAgeYears < 1) trustScore -= 25;

      // Giảm điểm nếu tên nghi ngờ
      const suspiciousWords = ["free", "giveaway", "login", "xn--", "bonus", "prize"];
      if (suspiciousWords.some(w => domain.includes(w))) trustScore -= 20;

      // Nếu API Google báo nguy hiểm
      if (isUnsafe) {
        trustScore = 10;
        trustLevel = "Thấp";
        warning = "🚨 Cảnh báo: Trang web có dấu hiệu lừa đảo hoặc chứa mã độc!";
      }

      // Gắn mức độ tin cậy
      if (trustScore >= 80) trustLevel = "Cao";
      else if (trustScore >= 50) trustLevel = "Trung bình";
      else trustLevel = "Thấp";

      // 4️⃣ Trả kết quả
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          website: url,
          domain,
          trustScore,
          trustLevel,
          warning,
          domainAgeYears,
          isUnsafe,
          checkedAt: new Date().toISOString()
        })
      };
    } catch (error) {
      return {
        statusCode: 500,
        body: JSON.stringify({
          error: "Lỗi xử lý URL hoặc kiểm tra API thất bại.",
          details: error.message
        })
      };
    }
  }

  // ====== Mặc định ======
  return {
    statusCode: 404,
    body: JSON.stringify({ error: "Không tìm thấy endpoint!" })
  };
};
