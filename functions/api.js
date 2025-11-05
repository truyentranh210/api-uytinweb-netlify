const axios = require("axios");

const GOOGLE_API_KEY = "AIzaSyBk1ABUXXTfzb5JVCk_jSzDUn0GfjMci9I"; // 🔑 Điền API Key tại đây
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`;

exports.handler = async (event) => {
  const path = event.path.split("/").pop();
  const params = event.queryStringParameters || {};

  // === /home ===
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

  // === /antoan ===
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

      // --- Gọi Google Safe Browsing API ---
      const response = await axios.post(SAFE_BROWSING_URL, {
        client: {
          clientId: "safecheck-app",
          clientVersion: "1.0"
        },
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

      const isUnsafe = response.data && response.data.matches;

      // --- Phân tích độ tin cậy ---
      let trustScore = 95;
      let trustLevel = "Cao";
      let warning = "✅ Trang web an toàn để truy cập.";

      if (isUnsafe) {
        trustScore = 20;
        trustLevel = "Thấp";
        warning =
          "🚨 Cảnh báo: Trang web có dấu hiệu chứa mã độc hoặc lừa đảo! Không nên truy cập.";
      } else if (
        domain.includes("free") ||
        domain.includes("giveaway") ||
        domain.includes("login") ||
        domain.includes("xn--")
      ) {
        trustScore = 60;
        trustLevel = "Trung bình";
        warning =
          "⚠️ Có thể là trang quảng cáo hoặc giả mạo. Hãy kiểm tra kỹ nguồn trước khi truy cập.";
      }

      // --- Trả về kết quả JSON ---
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          website: url,
          domain,
          trustLevel,
          trustScore,
          warning,
          checkedAt: new Date().toISOString()
        })
      };
    } catch (error) {
      return {
        statusCode: 500,
        body: JSON.stringify({
          error: "Không thể phân tích URL hoặc lỗi từ API.",
          details: error.message
        })
      };
    }
  }

  // --- Mặc định ---
  return {
    statusCode: 404,
    body: JSON.stringify({ error: "Không tìm thấy endpoint!" })
  };
};
