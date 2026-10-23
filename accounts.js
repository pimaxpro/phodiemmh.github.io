/**
 * ============================================================================
 * FILE QUẢN LÝ TÀI KHOẢN ĐĂNG NHẬP NỘI BỘ — TRUNG TÂM MINH HOÀNG
 * (Lưu hành nội bộ - Chỉ truy cập qua liên kết nội bộ & tài khoản được cấp)
 * ============================================================================
 * Hướng dẫn cấu hình:
 * 1. role:
 *    - 'ADMIN': Tài khoản cao nhất. Có quyền kéo thả/tải lên file điểm các lần thi,
 *               xóa đợt thi, nạp lại dữ liệu gốc và xem TẤT CẢ phổ điểm các môn.
 *    - 'USER' : Tài khoản giáo viên / quản lý bộ môn. Chỉ được XEM phổ điểm của
 *               đúng bộ môn mình quản lý (khai báo trong mảng `subjects`),
 *               KHÔNG thấy và KHÔNG được phép kéo thả/tải file dữ liệu.
 *
 * 2. subjects:
 *    - Với ADMIN: để ['ALL'] (xem toàn bộ các môn).
 *    - Với USER : liệt kê tên bộ môn được phép xem:
 *      + Tổ Toán THPT : ['Toán THPT']
 *      + Tổ Toán THCS : ['Toán THCS']
 *      + Tổ Ngữ Văn   : ['Ngữ Văn']
 *      + Tổ Tiếng Anh : ['Tiếng Anh']
 *      + Tổ KHTN      : ['KHTN (Lí)', 'KHTN (Hóa)', 'KHTN (Sinh)'] (1 tài khoản xem cả 3 phân môn KHTN)
 *
 * 3. Chính sách bảo mật nội bộ:
 *    - Giới hạn tối đa 7 thiết bị đăng nhập đồng thời trên mỗi tài khoản (maxDevicesPerAccount: 7).
 *    - Tự động đăng xuất sau 2 tiếng (120 phút) không hoạt động (sessionTimeoutMinutes: 120).
 *    - Dữ liệu tài khoản được nạp vào vùng nhớ bảo mật (Private Closure) và tự động xóa
 *      khỏi biến toàn cục `window` ngay khi khởi chạy.
 * ============================================================================
 */

window.ACCOUNT_CONFIG = {
  securitySettings: {
    maxFailedAttempts: 5,          // Số lần nhập sai tối đa trước khi khóa tạm thời
    lockoutDurationSeconds: 60,    // Thời gian khóa tạm thời khi nhập sai quá số lần (giây)
    sessionTimeoutMinutes: 120,    // Tự động đăng xuất sau 2 tiếng (120 phút) không hoạt động
    maxDevicesPerAccount: 7,       // Mỗi tài khoản được đăng nhập tối đa trên 7 thiết bị
    protectDevToolsForUser: true,  // Chặn phím tắt F12 / Ctrl+U đối với tài khoản USER hoặc chưa đăng nhập
    internalOnlyMode: true,        // Chế độ lưu hành nội bộ (chỉ người có link và tài khoản mới truy cập được)
  },

  accounts: [
    // ========================================================================
    // 1. TÀI KHOẢN ADMIN (QUYỀN CAO NHẤT — TOÀN QUYỀN HỆ THỐNG)
    // ========================================================================
    {
      username: 'tuanmh',
      aliases: ['admin', 'adminmh'],
      password: '1111',
      role: 'ADMIN',
      displayName: 'Minh Tuấn (Admin)',
      subjects: ['ALL'],
    },
    {
      username: 'trangmh',
      password: '1111',
      role: 'ADMIN',
      displayName: 'Đinh Thu Trang (Admin)',
      subjects: ['ALL'],
    },
    {
      username: 'hoangmh',
      password: '1111',
      role: 'ADMIN',
      displayName: 'Nguyễn Minh Hoàng (Admin)',
      subjects: ['ALL'],
    },
    {
      username: 'vumh',
      password: '1111',
      role: 'ADMIN',
      displayName: 'Trần Minh Vũ (Admin)',
      subjects: ['ALL'],
    },

    // ========================================================================
    // 2. CÁC TÀI KHOẢN USER (CHỈ XEM BỘ MÔN MÌNH QUẢN LÝ, KHÔNG KÉO THẢ FILE)
    // ========================================================================
    {
      username: 'toanthptmh',
      aliases: ['toanthpt'],
      password: '1111',
      role: 'USER',
      displayName: 'Tổ Toán THPT',
      subjects: ['Toán THPT'],
    },
    {
      username: 'toanthcsmh',
      aliases: ['toanthcs'],
      password: '1111',
      role: 'USER',
      displayName: 'Tổ Toán THCS',
      subjects: ['Toán THCS'],
    },
    {
      username: 'vanmh',
      aliases: ['nguvan', 'nguvanmh'],
      password: '1111',
      role: 'USER',
      displayName: 'Tổ Ngữ Văn',
      subjects: ['Ngữ Văn'],
    },
    {
      username: 'anhmh',
      aliases: ['tienganh', 'tienganhmh'],
      password: '1111',
      role: 'USER',
      displayName: 'Tổ Tiếng Anh',
      subjects: ['Tiếng Anh'],
    },
    {
      username: 'khtnmh',
      aliases: ['khtn'],
      password: '1111',
      role: 'USER',
      displayName: 'Tổ KHTN (Lí - Hóa - Sinh)',
      subjects: ['KHTN (Lí)', 'KHTN (Hóa)', 'KHTN (Sinh)'],
    },
  ],
};
