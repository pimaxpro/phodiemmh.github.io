/**
 * HỆ THỐNG PHỔ ĐIỂM THI — TRUNG TÂM MINH HOÀNG
 * - Phổ điểm luôn tách riêng theo từng Môn & từng Khối (không gộp chung các khối khác nhau)
 * - Toàn cảnh các môn có bộ chọn Khối riêng cho từng môn
 * - Thiết kế biểu đồ Modern EdTech/FinTech (cột bo góc, màu chuyển sắc Gradient, nhãn ngang sắc nét)
 */

(function () {
  'use strict';

  const STORAGE_KEY = 'TRUNG_TAM_MINH_HOANG_SESSIONS_V5_REAL_L1';
  const CENTER_NAME_KEY = 'TRUNG_TAM_MINH_HOANG_NAME_V2';
  const AUTH_SESSION_KEY = 'MH_AUTH_SECURE_TOKEN_V1';
  const AUTH_LOCKOUT_KEY = 'MH_AUTH_BRUTEFORCE_GUARD_V1';
  const DEVICE_ID_KEY = 'MH_DEVICE_FINGERPRINT_V1';
  const ACTIVE_DEVICES_KEY = 'MH_ACTIVE_DEVICE_SESSIONS_V1';
  const AUTH_SIGNATURE_SALT = 'MH_SECURE_SALT_2026_#27397c_#ee642c';

  const state = {
    currentUser: null, // Authenticated user object { username, role, displayName, subjects }
    sessions: [],
    currentSessionId: null,
    currentSubject: null,
    filterGrade: null, // Always a specific grade (e.g., '10', '11', '12') — never 'ALL'
    filterTeacher: 'ALL',
    overviewSelectedGrades: {}, // { [subject]: grade } for "Toàn cảnh các môn"
    binStep: 0.5,
    showBellCurve: true,
    topN: 0, // 0 = Tất cả học sinh, >0 = Giới hạn Top N điểm cao
    includeTies: true,
    showAllSubjectsTop: false,
    groupStatMode: 'teacher_by_grade',
    compareGradeFilter: 'ALL',
    viewMode: 'all',
    centerName: 'TRUNG TÂM MINH HOÀNG',
    studentSearchQuery: '',
    studentStatusFilter: 'ALL',
    pendingUploadRows: null,
    chartAnimProgress: 1,
    chartAnimFrameId: null,
    chartBarRects: [],
    selectedBinIndex: null,
  };

  function normalizeSubjectName(raw) {
    if (!raw) return 'Chưa phân loại';
    const cleaned = raw.trim().replace(/\s+/g, ' ');
    const upper = cleaned.toUpperCase();
    const map = {
      'TOÁN THPT': 'Toán THPT',
      'TOÁN THCS': 'Toán THCS',
      'NGỮ VĂN': 'Ngữ Văn',
      'TIẾNG ANH': 'Tiếng Anh',
      'KHTN (LÍ)': 'KHTN (Lí)',
      'KHTN (LÝ)': 'KHTN (Lí)',
      'KHTN (HÓA)': 'KHTN (Hóa)',
      'KHTN (HOÁ)': 'KHTN (Hóa)',
      'KHTN (SINH)': 'KHTN (Sinh)',
    };
    return map[upper] || cleaned;
  }

  // ============================================================================
  // HIGH-SECURITY AUTHENTICATION VAULT & RBAC ENGINE
  // ============================================================================
  function computeSecureDigest(input) {
    const str = String(input || '') + '::' + AUTH_SIGNATURE_SALT;
    let h1 = 0xdeadbeef ^ str.length;
    let h2 = 0x41c6ce57 ^ str.length;
    let h3 = 0x9e3779b9 ^ str.length;
    let h4 = 0x85ebca6b ^ str.length;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
      h3 = Math.imul(h3 ^ ch, 2246822507);
      h4 = Math.imul(h4 ^ ch, 3266489909);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    h3 = Math.imul(h3 ^ (h3 >>> 16), 2246822507) ^ Math.imul(h4 ^ (h4 >>> 13), 3266489909);
    h4 = Math.imul(h4 ^ (h4 >>> 16), 2246822507) ^ Math.imul(h3 ^ (h3 >>> 13), 3266489909);
    const hex = (n) => (n >>> 0).toString(16).padStart(8, '0');
    return hex(h1) + hex(h2) + hex(h3) + hex(h4);
  }

  function constantTimeEquals(a, b) {
    const sa = String(a || '');
    const sb = String(b || '');
    if (sa.length !== sb.length) return false;
    let diff = 0;
    for (let i = 0; i < sa.length; i++) {
      diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
    }
    return diff === 0;
  }

  // Capture & wipe window.ACCOUNT_CONFIG immediately so it cannot be read from DevTools console
  const PRIVATE_AUTH_VAULT = (function initPrivateVault() {
    const rawCfg = window.ACCOUNT_CONFIG || {};
    try {
      delete window.ACCOUNT_CONFIG;
    } catch (e) {
      window.ACCOUNT_CONFIG = undefined;
    }
    const sec = Object.assign(
      {
        maxFailedAttempts: 5,
        lockoutDurationSeconds: 60,
        sessionTimeoutMinutes: 120,
        maxDevicesPerAccount: 7,
        protectDevToolsForUser: true,
        internalOnlyMode: true,
      },
      rawCfg.securitySettings || {}
    );
    const rawAccounts = Array.isArray(rawCfg.accounts) ? rawCfg.accounts : [];
    const accounts = rawAccounts.map((acc) => {
      const uname = String(acc.username || '').trim().toLowerCase();
      const aliases = Array.isArray(acc.aliases)
        ? acc.aliases.map((a) => String(a || '').trim().toLowerCase()).filter(Boolean)
        : [];
      const role = String(acc.role || 'USER').trim().toUpperCase() === 'ADMIN' ? 'ADMIN' : 'USER';
      const subjs = Array.isArray(acc.subjects)
        ? acc.subjects.map((s) => (String(s).toUpperCase() === 'ALL' ? 'ALL' : normalizeSubjectName(s)))
        : [];
      const pwdDigest = computeSecureDigest(`${uname}::${String(acc.password || '')}`);
      return Object.freeze({
        username: uname,
        aliases: Object.freeze(aliases),
        passwordDigest: pwdDigest,
        role,
        displayName: String(acc.displayName || acc.username || 'Người dùng').trim(),
        subjects: Object.freeze(role === 'ADMIN' ? ['ALL'] : subjs),
      });
    });
    return Object.freeze({ settings: Object.freeze(sec), accounts: Object.freeze(accounts) });
  })();

  function signSessionPayload(userObj, exp) {
    const raw = `${userObj.username}|${userObj.role}|${(userObj.subjects || []).join(',')}|${exp}`;
    return computeSecureDigest(raw);
  }

  function isAuthenticated() {
    return Boolean(state.currentUser && state.currentUser.username);
  }

  function isAdminUser() {
    return Boolean(state.currentUser && state.currentUser.role === 'ADMIN');
  }

  function isSubjectAllowedForCurrentUser(subject) {
    if (!isAuthenticated() || !subject) return false;
    if (isAdminUser() || (state.currentUser.subjects && state.currentUser.subjects.includes('ALL'))) {
      return true;
    }
    const normTarget = normalizeSubjectName(subject);
    const allowedSet = new Set();
    (state.currentUser.subjects || []).forEach((s) => {
      const norm = normalizeSubjectName(s);
      allowedSet.add(norm);
      if (norm.toUpperCase() === 'KHTN' || norm.toUpperCase().startsWith('KHTN')) {
        allowedSet.add('KHTN (Lí)');
        allowedSet.add('KHTN (Hóa)');
        allowedSet.add('KHTN (Sinh)');
      }
    });
    return allowedSet.has(normTarget);
  }

  function getAllowedSubjects(session) {
    if (!session || !Array.isArray(session.subjects)) return [];
    if (!isAuthenticated()) return [];
    return session.subjects.filter((s) => isSubjectAllowedForCurrentUser(s));
  }

  function parseCSVToRows(csvText) {
    const text = csvText.replace(/^\uFEFF/, '');
    const rows = [];
    let curRow = [];
    let curVal = '';
    let inQuotes = false;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      const next = text[i + 1];

      if (inQuotes) {
        if (ch === '"' && next === '"') {
          curVal += '"';
          i++;
        } else if (ch === '"') {
          inQuotes = false;
        } else {
          curVal += ch;
        }
      } else {
        if (ch === '"') {
          inQuotes = true;
        } else if (ch === ',') {
          curRow.push(curVal);
          curVal = '';
        } else if (ch === '\r' && next === '\n') {
          curRow.push(curVal);
          rows.push(curRow);
          curRow = [];
          curVal = '';
          i++;
        } else if (ch === '\n' || ch === '\r') {
          curRow.push(curVal);
          rows.push(curRow);
          curRow = [];
          curVal = '';
        } else {
          curVal += ch;
        }
      }
    }
    if (curVal.length > 0 || curRow.length > 0) {
      curRow.push(curVal);
      rows.push(curRow);
    }
    return rows;
  }

  function isAbsentMarker(str) {
    if (!str) return false;
    const s = String(str).trim().toLowerCase();
    return s === 'x' || s === 'vắng' || s === 'vang' || s === 'v' || s === 'k' || s === 'kt' || s === 'nghỉ';
  }

  function normalizeGradeValue(raw) {
    if (!raw) return '';
    const s = String(raw).trim();
    const num = parseFloat(s);
    if (!isNaN(num) && isFinite(num) && num >= 1 && num <= 12) {
      return String(Math.round(num));
    }
    return s;
  }

  function parseScoreFromCell(rawScoreStr) {
    if (rawScoreStr === null || rawScoreStr === undefined || rawScoreStr === '') return null;
    const normalizedNum = String(rawScoreStr).replace(',', '.').trim();
    const parsed = parseFloat(normalizedNum);
    if (isNaN(parsed) || !isFinite(parsed)) return null;
    // Recover scores that Excel auto-converted into Date Serial Numbers (e.g. 6.5 -> 6 May -> 46148)
    if (parsed > 35000 && parsed < 60000) {
      const utcDays = Math.round(parsed - 25569);
      const dt = new Date(utcDays * 86400 * 1000);
      const recovered = parseFloat(`${dt.getUTCDate()}.${dt.getUTCMonth() + 1}`);
      if (!isNaN(recovered) && recovered >= 0 && recovered <= 10) {
        return Math.round(recovered * 1000) / 1000;
      }
      return null;
    }
    if (parsed >= 0 && parsed <= 10) {
      return Math.round(parsed * 1000) / 1000;
    }
    return null;
  }

  function parseCenterRows(rows) {
    let currentSubject = 'Chung';
    let currentTeacher = 'Chưa rõ';
    let lastKnownGrade = '9';
    let colMap = { stt: 0, name: 1, grade: 2, date: -1, score: 3, note: -1 };
    let seqStt = 0;

    const rawRecords = [];
    let validScoreCount = 0;
    let explicitAbsentCount = 0;

    for (let r = 0; r < rows.length; r++) {
      const row = rows[r].map((c) => (c == null ? '' : String(c).trim()));
      if (row.every((c) => c === '')) continue;

      const firstCell = row[0] || '';
      const firstUpper = firstCell.toUpperCase();

      let foundMeta = false;
      for (let c = 0; c < Math.min(3, row.length); c++) {
        const cellText = row[c];
        const cellUpper = cellText.toUpperCase();
        if (cellUpper.startsWith('BỘ MÔN:') || cellUpper.startsWith('MÔN:')) {
          const val = cellText.split(':')[1] || '';
          currentSubject = normalizeSubjectName(val);
          foundMeta = true;
          break;
        }
        if (cellUpper.startsWith('GV:') || cellUpper.startsWith('GIÁO VIÊN:')) {
          const val = cellText.split(':')[1] || '';
          currentTeacher = val.trim() || 'Chưa rõ';
          foundMeta = true;
          break;
        }
      }
      if (foundMeta) continue;
      if (firstUpper.includes('DANH SÁCH HỌC SINH')) continue;

      const upperHeaders = row.map((c) => c.toUpperCase());
      const isHeaderRow =
        firstUpper === 'STT' ||
        (upperHeaders.some((h) => h.includes('HỌC SINH') || h.includes('HỌ TÊN')) &&
          upperHeaders.some((h) => h === 'LỚP' || h.includes('KHỐI') || h.includes('ĐIỂM')));

      if (isHeaderRow) {
        const sttIdx = upperHeaders.findIndex((h) => h === 'STT');
        const nameIdx = upperHeaders.findIndex((h) => h.includes('HỌC SINH') || h.includes('HỌ TÊN') || h.includes('TÊN'));
        const gradeIdx = upperHeaders.findIndex((h) => h === 'LỚP' || h.includes('KHỐI'));
        const dateIdx = upperHeaders.findIndex((h) => h.includes('NGÀY THI'));
        const scoreIdx = upperHeaders.findIndex((h) => h.includes('ĐIỂM THI') || h === 'ĐIỂM');
        const noteIdx = upperHeaders.findIndex((h) => h.includes('GHI CHÚ'));

        colMap = {
          stt: sttIdx,
          name: nameIdx >= 0 ? nameIdx : sttIdx >= 0 ? 1 : 0,
          grade: gradeIdx >= 0 ? gradeIdx : sttIdx >= 0 ? 2 : 1,
          date: dateIdx,
          score: scoreIdx >= 0 ? scoreIdx : sttIdx >= 0 ? 3 : 2,
          note: noteIdx,
        };
        seqStt = 0;
        continue;
      }

      seqStt++;
      const sttRaw = colMap.stt >= 0 ? normalizeGradeValue(row[colMap.stt] || String(seqStt)) : String(seqStt);
      const studentName = (row[colMap.name] || '').trim();
      if (!studentName || studentName.toUpperCase() === 'HỌC SINH') continue;

      let gradeRaw = normalizeGradeValue(row[colMap.grade] || '');
      if (gradeRaw) {
        lastKnownGrade = gradeRaw;
      } else {
        gradeRaw = lastKnownGrade;
      }

      const examDate = colMap.date >= 0 ? (row[colMap.date] || '').trim() : '';
      const note = colMap.note >= 0 ? (row[colMap.note] || '').trim() : '';

      const rawScoreStr = colMap.score >= 0 && colMap.score < row.length ? row[colMap.score] : '';
      let score = null;
      let absent = false;

      if (isAbsentMarker(rawScoreStr) || isAbsentMarker(note)) {
        absent = true;
        explicitAbsentCount++;
      } else if (rawScoreStr !== '') {
        const parsedScore = parseScoreFromCell(rawScoreStr);
        if (parsedScore !== null) {
          score = parsedScore;
          validScoreCount++;
        }
      }

      rawRecords.push({
        id: 'rec-' + r + '-' + Math.random().toString(36).slice(2, 7),
        stt: sttRaw,
        name: studentName,
        grade: gradeRaw,
        subject: currentSubject,
        teacher: currentTeacher,
        examDate: examDate,
        score: score,
        absent: absent,
        note: note,
      });
    }

    let records = rawRecords;
    if (validScoreCount > 0) {
      // Filter out un-graded template teacher blocks that have 0 scores and 0 explicit 'x' marks
      const activeBlocks = new Set();
      rawRecords.forEach((rec) => {
        if (rec.score !== null || rec.absent) {
          activeBlocks.add(`${rec.subject}|||${rec.teacher}`);
        }
      });
      records = rawRecords.filter((rec) => activeBlocks.has(`${rec.subject}|||${rec.teacher}`));
      records.forEach((rec) => {
        if (rec.score === null) rec.absent = true;
      });
    }

    return {
      records,
      totalRecords: records.length,
      validScoreCount,
      explicitAbsentCount,
      subjects: Array.from(new Set(records.map((r) => r.subject))),
    };
  }

  function fillMockScoresForRecords(records) {
    const subjParams = {
      'Toán THPT': [6.55, 1.6],
      'Ngữ Văn': [6.85, 1.35],
      'Tiếng Anh': [6.7, 1.8],
      'Toán THCS': [7.0, 1.55],
      'KHTN (Lí)': [6.6, 1.65],
      'KHTN (Hóa)': [6.45, 1.7],
      'KHTN (Sinh)': [7.1, 1.4],
    };

    let seed = Date.now() % 100000;
    function nextRand() {
      seed = (seed * 16807) % 2147483647;
      return (seed - 1) / 2147483646;
    }
    function nextGauss(mean, std) {
      const u1 = Math.max(1e-7, nextRand());
      const u2 = nextRand();
      const z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
      return mean + z0 * std;
    }

    return records.map((rec) => {
      if (rec.score !== null && !isNaN(rec.score)) return rec;
      const [m, s] = subjParams[rec.subject] || [6.6, 1.6];
      const r = nextRand();
      if (r < 0.05) {
        return Object.assign({}, rec, { score: null, absent: true });
      }
      let val;
      if (r < 0.088) {
        val = 10;
      } else if (r < 0.095) {
        val = [0, 0.5, 0.75, 1.0][Math.floor(nextRand() * 4)];
      } else {
        val = Math.max(0.5, Math.min(9.75, nextGauss(m, s)));
        val = Math.round(val * 4) / 4;
      }
      return Object.assign({}, rec, { score: val, absent: false });
    });
  }

  // ============================================================================
  // STATISTICAL ENGINE
  // ============================================================================
  function computeStatistics(records, binStep = 0.5) {
    const totalRoster = records.length;
    const scoredRecords = records.filter(
      (r) => !r.absent && r.score !== null && !isNaN(r.score) && r.score >= 0 && r.score <= 10
    );
    const absentRecords = records.filter((r) => r.absent || r.score === null || isNaN(r.score));
    const n = scoredRecords.length;
    const absentCount = absentRecords.length;
    const absentPct = totalRoster > 0 ? (absentCount / totalRoster) * 100 : 0;

    const scores = scoredRecords.map((r) => r.score).sort((a, b) => a - b);

    const numBins = Math.round(10 / binStep);
    const bins = [];
    for (let i = 0; i < numBins; i++) {
      const low = Math.round(i * binStep * 100) / 100;
      const high = Math.round((i + 1) * binStep * 100) / 100;
      const label = i === 0 ? `[${low}, ${high}]` : `(${low}, ${high}]`;
      const shortLabel = `${low}–${high}`;
      bins.push({ index: i, low, high, mid: (low + high) / 2, label, shortLabel, count: 0, pct: 0, students: [] });
    }

    for (let i = 0; i < n; i++) {
      const rec = scoredRecords[i];
      const s = rec.score;
      let idx = s <= binStep + 1e-9 ? 0 : Math.ceil(s / binStep - 1e-9) - 1;
      idx = Math.max(0, Math.min(numBins - 1, idx));
      bins[idx].count++;
      bins[idx].students.push(rec);
    }

    for (let i = 0; i < numBins; i++) {
      bins[i].pct = n > 0 ? (bins[i].count / n) * 100 : 0;
      bins[i].students.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name, 'vi'));
    }

    if (n === 0) {
      return {
        totalRoster,
        count: 0,
        absentCount,
        absentPct,
        mean: 0,
        median: 0,
        maxScore: 0,
        minScore: 0,
        stdDev: 0,
        mad: 0,
        lt5Count: 0,
        lt5Pct: 0,
        gte7Count: 0,
        gte7Pct: 0,
        gte8Count: 0,
        gte8Pct: 0,
        mode: 0,
        modeCount: 0,
        score10Count: 0,
        score0Count: 0,
        lte1Count: 0,
        lte1Pct: 0,
        per1000Score10: 0,
        bins,
        maxBinCount: 0,
      };
    }

    let sum = 0;
    for (let i = 0; i < n; i++) sum += scores[i];
    const mean = sum / n;
    const minScore = scores[0];
    const maxScore = scores[n - 1];

    const midIdx = Math.floor(n / 2);
    const median = n % 2 === 1 ? scores[midIdx] : (scores[midIdx - 1] + scores[midIdx]) / 2;

    let sqDiffSum = 0;
    for (let i = 0; i < n; i++) {
      const d = scores[i] - mean;
      sqDiffSum += d * d;
    }
    const stdDev = Math.sqrt(sqDiffSum / n);

    const absDevs = scores.map((x) => Math.abs(x - median)).sort((a, b) => a - b);
    const mad = n % 2 === 1 ? absDevs[midIdx] : (absDevs[midIdx - 1] + absDevs[midIdx]) / 2;

    let lt5Count = 0;
    let gte7Count = 0;
    let gte8Count = 0;
    let score10Count = 0;
    let score0Count = 0;
    let lte1Count = 0;

    const freqMap = new Map();
    for (let i = 0; i < n; i++) {
      const s = scores[i];
      if (s < 5 - 1e-9) lt5Count++;
      if (s >= 7 - 1e-9) gte7Count++;
      if (s >= 8 - 1e-9) gte8Count++;
      if (Math.abs(s - 10) < 1e-9) score10Count++;
      if (Math.abs(s) < 1e-9) score0Count++;
      if (s <= 1 + 1e-9) lte1Count++;

      const key = Math.round(s * 100) / 100;
      freqMap.set(key, (freqMap.get(key) || 0) + 1);
    }

    let mode = scores[0];
    let modeCount = 0;
    freqMap.forEach((cnt, val) => {
      if (cnt > modeCount || (cnt === modeCount && val > mode)) {
        modeCount = cnt;
        mode = val;
      }
    });

    const maxBinCount = Math.max(...bins.map((b) => b.count), 1);

    return {
      totalRoster,
      count: n,
      absentCount,
      absentPct,
      mean,
      median,
      maxScore,
      minScore,
      stdDev,
      mad,
      lt5Count,
      lt5Pct: (lt5Count / n) * 100,
      gte7Count,
      gte7Pct: (gte7Count / n) * 100,
      gte8Count,
      gte8Pct: (gte8Count / n) * 100,
      mode,
      modeCount,
      score10Count,
      score0Count,
      lte1Count,
      lte1Pct: (lte1Count / n) * 100,
      per1000Score10: (score10Count / n) * 1000,
      bins,
      maxBinCount,
    };
  }

  function fmtInt(n) {
    return Number(n || 0).toLocaleString('en-US');
  }
  function fmtDec(n, digits = 2) {
    return Number(n || 0).toFixed(digits).replace(/\.?0+$/, (m) => (digits === 2 ? m : ''));
  }
  function fmtFixed(n, digits = 2) {
    return Number(n || 0).toFixed(digits);
  }
  function fmtPct(n, digits = 2) {
    return Number(n || 0).toFixed(digits) + ' %';
  }

  // ============================================================================
  // INITIALIZE & GRADE ENFORCEMENT (Never combine all grades!)
  // ============================================================================
  function getGradesForSubject(session, subject) {
    if (!session || !isSubjectAllowedForCurrentUser(subject)) return [];
    const subjRecords = session.records.filter((r) => r.subject === subject);
    return Array.from(new Set(subjRecords.map((r) => String(r.grade)).filter((g) => g && g !== 'Chưa rõ'))).sort(
      (a, b) => Number(a) - Number(b)
    );
  }

  function ensureValidGradeAndTeacher() {
    const sess = getCurrentSession();
    if (!sess) return;
    if (!isAuthenticated()) return;

    const allowedSubjs = getAllowedSubjects(sess);
    if (!state.currentSubject || !allowedSubjs.includes(state.currentSubject) || !isSubjectAllowedForCurrentUser(state.currentSubject)) {
      if (allowedSubjs.length > 0) {
        state.currentSubject = allowedSubjs[0];
      } else if (isAdminUser()) {
        state.currentSubject = sess.subjects[0] || 'Toán THPT';
      } else {
        state.currentSubject = normalizeSubjectName(state.currentUser?.subjects?.[0] || '');
      }
    }

    const grades = getGradesForSubject(sess, state.currentSubject);
    if (grades.length > 0) {
      if (!state.filterGrade || state.filterGrade === 'ALL' || !grades.includes(String(state.filterGrade))) {
        state.filterGrade = grades[0];
      }
    } else {
      state.filterGrade = '';
    }

    // Ensure teacher exists in this (subject, grade)
    if (state.filterTeacher !== 'ALL') {
      const teachersInGrade = sess.records
        .filter((r) => r.subject === state.currentSubject && String(r.grade) === String(state.filterGrade))
        .map((r) => r.teacher);
      if (!teachersInGrade.includes(state.filterTeacher)) {
        state.filterTeacher = 'ALL';
      }
    }
  }

  function sortSessionsByOrder(sessions) {
    return sessions.slice().sort((a, b) => {
      const mA = String(a.fileCode || a.name || '').match(/L(\d+)/i);
      const mB = String(b.fileCode || b.name || '').match(/L(\d+)/i);
      if (mA && mB) return parseInt(mA[1], 10) - parseInt(mB[1], 10);
      if (mA) return -1;
      if (mB) return 1;
      return 0;
    });
  }

  function parseWorkbookBufferToRows(arrayBuffer) {
    const data = new Uint8Array(arrayBuffer);
    const workbook = window.XLSX.read(data, { type: 'array' });
    let allRows = [];
    workbook.SheetNames.forEach((sheetName) => {
      const sheet = workbook.Sheets[sheetName];
      const sheetRows = window.XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
      allRows = allRows.concat(sheetRows);
    });
    return allRows;
  }

  function cleanSessionLabel(raw) {
    return String(raw || '')
      .replace(/\s*\([lL]\d+\.(xlsx|xls|csv)\)/g, '')
      .trim();
  }

  function upsertAdminSessionFromParsed(num, fileName, parsed) {
    if (!parsed || parsed.totalRecords === 0) return null;
    const id = `admin-L${num}`;
    const fileCode = `L${num}`;
    const sessObj = {
      id,
      fileCode,
      fileName,
      isAdminFile: true,
      name: `Lần thi ${num}`,
      shortName: `Lần ${num}`,
      date: new Date().toLocaleDateString('vi-VN'),
      records: parsed.records,
      subjects: parsed.subjects,
    };
    const existingIdx = state.sessions.findIndex((s) => s.id === id || s.fileCode === fileCode);
    if (existingIdx >= 0) {
      state.sessions[existingIdx] = sessObj;
    } else {
      state.sessions.push(sessObj);
    }
    state.sessions = sortSessionsByOrder(state.sessions);
    return sessObj;
  }

  async function autoScanFolderExamFiles(showNotice = false) {
    if (window.location.protocol === 'file:') return;
    let syncedAny = false;
    for (let k = 1; k <= 12; k++) {
      const candidates = [`L${k}.xlsx`, `L${k}.csv`, `l${k}.xlsx`, `l${k}.csv`];
      for (let c = 0; c < candidates.length; c++) {
        const fname = candidates[c];
        try {
          const resp = await fetch(`./${fname}`, { cache: 'no-store' });
          if (!resp.ok) continue;
          let rows = [];
          if (fname.toLowerCase().endsWith('.csv')) {
            const text = await resp.text();
            rows = parseCSVToRows(text);
          } else {
            const buf = await resp.arrayBuffer();
            rows = parseWorkbookBufferToRows(buf);
          }
          const parsed = parseCenterRows(rows);
          if (parsed.totalRecords > 0) {
            upsertAdminSessionFromParsed(k, fname.toUpperCase().replace('.XLSX', '.xlsx').replace('.CSV', '.csv'), parsed);
            syncedAny = true;
            break;
          }
        } catch (err) {
          // Ignore missing files L2, L3... when probing folder
        }
      }
    }
    if (syncedAny || showNotice) {
      ensureValidGradeAndTeacher();
      saveSessionsToStorage();
      refreshAllUI(false);
      if (showNotice) {
        showToast(`Đã quét thư mục: phát hiện ${state.sessions.length} lần thi (${state.sessions.map((s) => s.fileCode || s.shortName).join(', ')})`);
      }
    }
  }

  function loadInitialData() {
    const savedCenterName = localStorage.getItem(CENTER_NAME_KEY);
    state.centerName = savedCenterName || 'TRUNG TÂM MINH HOÀNG';
    const nameInput = document.getElementById('centerNameInput');
    if (nameInput) nameInput.value = state.centerName;

    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          parsed.forEach((s, idx) => {
            if (!s.fileName) {
              const m = String(s.shortName || s.name || '').match(/\(([lL]\d+\.[a-zA-Z0-9]+)\)/);
              s.fileName = m ? m[1] : `L${idx + 1}.xlsx`;
            }
            s.name = cleanSessionLabel(s.name);
            s.shortName = cleanSessionLabel(s.shortName);
          });
          state.sessions = sortSessionsByOrder(parsed);
          state.currentSessionId = state.sessions[0].id;
          ensureValidGradeAndTeacher();
          autoScanFolderExamFiles(false);
          return;
        }
      }
    } catch (e) {
      console.warn(e);
    }

    resetToDemoSessions(false);
    autoScanFolderExamFiles(false);
  }

  function resetToDemoSessions(showNotification = true) {
    if (!window.CENTER_SAMPLE_DATA || !window.CENTER_SAMPLE_DATA.sessions) return;
    state.sessions = window.CENTER_SAMPLE_DATA.sessions.map((s, idx) => {
      const rows = parseCSVToRows(s.csv);
      const parsed = parseCenterRows(rows);
      return {
        id: s.id || `admin-L${idx + 1}`,
        fileCode: s.fileCode || `L${idx + 1}`,
        fileName: s.fileName || `L${idx + 1}.xlsx`,
        isAdminFile: true,
        name: cleanSessionLabel(s.name) || `Lần thi ${idx + 1}`,
        shortName: cleanSessionLabel(s.shortName) || `Lần ${idx + 1}`,
        date: s.date,
        records: parsed.records,
        subjects: parsed.subjects,
      };
    });

    state.sessions = sortSessionsByOrder(state.sessions);
    state.currentSessionId = state.sessions[0].id;
    ensureValidGradeAndTeacher();
    saveSessionsToStorage();
    if (showNotification) {
      autoScanFolderExamFiles(true);
      showToast('Đã nạp lại dữ liệu gốc L1.xlsx của Trung tâm Minh Hoàng');
      refreshAllUI(true);
    }
  }

  function saveSessionsToStorage() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state.sessions));
    } catch (e) {
      console.warn(e);
    }
  }

  function getCurrentSession() {
    return state.sessions.find((s) => s.id === state.currentSessionId) || state.sessions[0];
  }

  function getFilteredRecords(session, subject, teacher = 'ALL', grade = null) {
    if (!session || !isAuthenticated()) return [];
    return session.records.filter((r) => {
      if (!isSubjectAllowedForCurrentUser(r.subject)) return false;
      if (subject && subject !== 'ALL' && r.subject !== subject) return false;
      if (grade && grade !== 'ALL' && String(r.grade) !== String(grade)) return false;
      if (teacher && teacher !== 'ALL' && r.teacher !== teacher) return false;
      return true;
    });
  }

  // ============================================================================
  // UI RENDERING
  // ============================================================================
  function renderSessionPills() {
    // 1. Render Top Dropdown Menu (#topSessionDropdown) — concise, no leading icons, normal font
    const selectEl = document.getElementById('topSessionDropdown');
    if (selectEl) {
      let html = '';
      state.sessions.forEach((sess) => {
        const sel = state.viewMode !== 'multisession' && sess.id === state.currentSessionId ? 'selected' : '';
        const label = sess.shortName || sess.name;
        html += `<option value="${escapeHtml(sess.id)}" ${sel}>${escapeHtml(label)}</option>`;
      });

      const compareSel = state.viewMode === 'multisession' ? 'selected' : '';
      html += `<option value="__COMPARE_ALL__" ${compareSel}>So sánh các lần thi</option>`;

      selectEl.innerHTML = html;
    }

    // Show/hide delete button if more than 1 session AND logged in as ADMIN
    const delBtn = document.getElementById('btnDeleteCurrentSession');
    if (delBtn) {
      delBtn.style.display = isAdminUser() && state.sessions.length > 1 ? 'inline-flex' : 'none';
    }

    // 2. Render Status Pills inside Top Bar Footer (#sessionPillsContainer)
    const container = document.getElementById('sessionPillsContainer');
    if (!container) return;
    container.innerHTML = '';

    state.sessions.forEach((sess) => {
      const isActive = sess.id === state.currentSessionId;
      const allowedRecs = sess.records.filter((r) => isSubjectAllowedForCurrentUser(r.subject));
      const scoredCount = allowedRecs.filter((r) => !r.absent && r.score !== null).length;
      const absentCount = allowedRecs.filter((r) => r.absent || r.score === null).length;
      const pill = document.createElement('div');
      pill.className = 'session-pill' + (isActive ? ' active' : '');
      pill.innerHTML = `
        <span>${escapeHtml(sess.shortName || sess.name)}</span>
        <span class="pill-count">${fmtInt(scoredCount)} TS${absentCount > 0 ? ` • ${absentCount} vắng` : ''}</span>
        ${
          isAdminUser() && state.sessions.length > 1
            ? `<span class="pill-delete" data-del-id="${escapeHtml(sess.id)}" title="Xóa">✕</span>`
            : ''
        }
      `;
      pill.addEventListener('click', (e) => {
        const dBtn = e.target.closest('[data-del-id]');
        if (dBtn) {
          e.stopPropagation();
          deleteSession(dBtn.getAttribute('data-del-id'));
          return;
        }
        if (state.currentSessionId !== sess.id || state.viewMode === 'multisession') {
          state.currentSessionId = sess.id;
          if (state.viewMode === 'multisession') {
            state.viewMode = 'all';
            updateViewModeVisibility();
          }
          ensureValidGradeAndTeacher();
          refreshAllUI(true);
        }
      });
      container.appendChild(pill);
    });
  }

  function deleteSession(id) {
    if (!isAdminUser()) {
      showToast('Chỉ tài khoản ADMIN mới được phép xóa đợt thi!');
      return;
    }
    if (state.sessions.length <= 1) return;
    state.sessions = state.sessions.filter((s) => s.id !== id);
    if (state.currentSessionId === id) {
      state.currentSessionId = state.sessions[state.sessions.length - 1].id;
    }
    ensureValidGradeAndTeacher();
    saveSessionsToStorage();
    refreshAllUI(true);
  }

  function getSubjectIconClass(subj) {
    const s = String(subj || '').toLowerCase();
    if (s.includes('toán')) return 'fa-solid fa-square-root-variable';
    if (s.includes('lý') || s.includes('lí') || s.includes('vật')) return 'fa-solid fa-atom';
    if (s.includes('hóa')) return 'fa-solid fa-flask';
    if (s.includes('sinh')) return 'fa-solid fa-dna';
    if (s.includes('anh') || s.includes('ngoại')) return 'fa-solid fa-language';
    if (s.includes('văn')) return 'fa-solid fa-feather-pointed';
    if (s.includes('sử')) return 'fa-solid fa-landmark';
    if (s.includes('địa')) return 'fa-solid fa-earth-asia';
    if (s.includes('tin')) return 'fa-solid fa-laptop-code';
    return 'fa-solid fa-book';
  }

  function renderSubjectTabs() {
    const sess = getCurrentSession();
    const container = document.getElementById('subjectTabsContainer');
    if (!container || !sess) return;
    container.innerHTML = '';

    const allowedSubjs = getAllowedSubjects(sess);
    allowedSubjs.forEach((subj) => {
      const iconCls = getSubjectIconClass(subj);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'subject-tab' + (state.currentSubject === subj ? ' active' : '');
      btn.innerHTML = `
        <span class="subj-tab-left"><i class="${iconCls}"></i> <span>${escapeHtml(subj)}</span></span>
      `;
      btn.addEventListener('click', () => {
        if (window.innerWidth <= 960) {
          document.body.classList.remove('sidebar-mobile-open');
        }
        if (state.currentSubject !== subj) {
          state.currentSubject = subj;
          state.filterTeacher = 'ALL';
          state.compareGradeFilter = 'ALL';
          ensureValidGradeAndTeacher();
          refreshAllUI(true);
        }
      });
      container.appendChild(btn);
    });
  }

  function renderTeacherAndGradeFilters() {
    const sess = getCurrentSession();
    if (!sess) return;
    ensureValidGradeAndTeacher();

    const subjRecords = getFilteredRecords(sess, state.currentSubject, 'ALL', 'ALL');
    const grades = getGradesForSubject(sess, state.currentSubject);

    // 1. Render Quick Grade Pills (ONLY individual grades — NO "Tất cả Khối")
    const gradePillsWrap = document.getElementById('quickGradePills');
    if (gradePillsWrap) {
      let gHtml = `<span class="filter-group-label" title="Chọn Khối thi môn ${escapeHtml(state.currentSubject)}"><i class="fa-solid fa-layer-group"></i> Khối</span>`;
      grades.forEach((g) => {
        const cnt = subjRecords.filter(
          (r) => String(r.grade) === String(g) && !r.absent && r.score !== null
        ).length;
        const active = String(state.filterGrade) === String(g) ? 'active' : '';
        gHtml += `<button type="button" class="choice-pill ${active}" data-g-pill="${escapeHtml(String(g))}" title="Khối ${escapeHtml(String(g))} (${cnt} thí sinh dự thi)"><span>Khối ${escapeHtml(String(g))}</span><span class="cp-count">${cnt}</span></button>`;
      });
      gradePillsWrap.innerHTML = gHtml;

      gradePillsWrap.querySelectorAll('[data-g-pill]').forEach((btn) => {
        btn.addEventListener('click', () => {
          state.filterGrade = btn.getAttribute('data-g-pill');
          state.filterTeacher = 'ALL';
          refreshAllUI(true);
        });
      });
    }

    // 2. Render Quick Teacher Pills (Only teachers who teach the selected Grade of this Subject)
    const gradeRecords = subjRecords.filter((r) => String(r.grade) === String(state.filterGrade));
    const teachersInGrade = Array.from(new Set(gradeRecords.map((r) => r.teacher).filter(Boolean)));

    const teacherPillsWrap = document.getElementById('quickTeacherPills');
    if (teacherPillsWrap) {
      const totalGradeTested = gradeRecords.filter((r) => !r.absent && r.score !== null).length;
      let tHtml = `<span class="filter-group-label" title="Giáo viên dạy Khối ${escapeHtml(String(state.filterGrade))}"><i class="fa-solid fa-chalkboard-user"></i> Giáo viên</span>`;
      tHtml += `<button type="button" class="choice-pill ${state.filterTeacher === 'ALL' ? 'active' : ''}" data-t-pill="ALL" title="Tổng hợp cả nhóm Khối ${escapeHtml(String(state.filterGrade))} (${teachersInGrade.length} giáo viên • ${totalGradeTested} thí sinh)"><i class="fa-solid fa-users qf-pill-icon"></i><span>Cả nhóm (${teachersInGrade.length})</span><span class="cp-count">${totalGradeTested}</span></button>`;
      teachersInGrade.forEach((t) => {
        const cnt = gradeRecords.filter((r) => r.teacher === t && !r.absent && r.score !== null).length;
        const active = state.filterTeacher === t ? 'active' : '';
        tHtml += `<button type="button" class="choice-pill ${active}" data-t-pill="${escapeHtml(t)}" title="Giáo viên ${escapeHtml(t)} — Khối ${escapeHtml(String(state.filterGrade))} (${cnt} thí sinh)"><i class="fa-regular fa-user qf-pill-icon"></i><span>${escapeHtml(t)}</span><span class="cp-count">${cnt}</span></button>`;
      });
      teacherPillsWrap.innerHTML = tHtml;

      teacherPillsWrap.querySelectorAll('[data-t-pill]').forEach((btn) => {
        btn.addEventListener('click', () => {
          state.filterTeacher = btn.getAttribute('data-t-pill');
          refreshAllUI(true);
        });
      });
    }

    // 3. Compare Grade Filter in Section 3
    const compareGradeSelect = document.getElementById('compareGradeFilter');
    if (compareGradeSelect) {
      compareGradeSelect.innerHTML = `<option value="ALL">Tất cả Khối (${grades.length})</option>`;
      grades.forEach((g) => {
        const opt = document.createElement('option');
        opt.value = g;
        opt.textContent = `Khối ${g}`;
        if (String(state.compareGradeFilter) === String(g)) opt.selected = true;
        compareGradeSelect.appendChild(opt);
      });
    }
  }

  function updateTHPTMainSection(stats) {
    const sess = getCurrentSession();
    if (!sess) return;

    const teacherLabel = state.filterTeacher !== 'ALL' ? ` • GV ${state.filterTeacher}` : ' • Cả nhóm';

    document.getElementById('thptSubBannerText').textContent =
      `${state.currentSubject.toUpperCase()} — KHỐI ${state.filterGrade}${teacherLabel.toUpperCase()}`;

    document.getElementById('thptCenterTag').textContent =
      `${state.centerName}`;

    document.getElementById('statSoTS').textContent = fmtInt(stats.count);
    document.getElementById('statSoTSNote').textContent = `/${fmtInt(stats.totalRoster)} ĐK`;
    document.getElementById('statAbsentCount').textContent = fmtInt(stats.absentCount);
    document.getElementById('statAbsentPct').textContent = fmtPct(stats.absentPct, 2);
    document.getElementById('statDTB').textContent = fmtFixed(stats.mean, 2);
    document.getElementById('statMedian').textContent = fmtDec(stats.median, 2);
    document.getElementById('statDLC').textContent = fmtFixed(stats.stdDev, 2);
    document.getElementById('statMAD').textContent = fmtDec(stats.mad, 2);
    document.getElementById('statLt5Count').textContent = fmtInt(stats.lt5Count);
    document.getElementById('statLt5Pct').textContent = fmtPct(stats.lt5Pct, 2);
    document.getElementById('statGte7Count').textContent = fmtInt(stats.gte7Count);
    document.getElementById('statGte7Pct').textContent = fmtPct(stats.gte7Pct, 2);
    document.getElementById('statMode').textContent = fmtFixed(stats.mode, 2);
    document.getElementById('statModeCount').textContent = stats.modeCount > 0 ? `(${stats.modeCount} TS)` : '';
    document.getElementById('statScore10').textContent = fmtInt(stats.score10Count);
    document.getElementById('statScore10Pct').textContent =
      stats.count > 0 ? fmtPct((stats.score10Count / stats.count) * 100, 2) : '';
    document.getElementById('statScore0').textContent = fmtInt(stats.score0Count);
    document.getElementById('statLte1Count').textContent = fmtInt(stats.lte1Count);
    document.getElementById('statLte1Pct').textContent = fmtPct(stats.lte1Pct, 2);
  }

  // ============================================================================
  // LATEX FORMULA EXPLANATIONS FOR STATISTICAL INDICATORS (ULTRA-DETAILED)
  // ============================================================================
  const STAT_LATEX_EXPLANATIONS = {
    sots: {
      title: 'Số thí sinh dự thi thực tế',
      symbol: 'n',
      formula: 'n = N_{\\text{ĐK}} - n_{\\text{vắng}}',
      meaning:
        '<b>Bản chất:</b> Là cỡ mẫu thực tế ($n$) dùng ở mẫu số cho mọi công thức thống kê ($\\bar{x}, \\sigma, M_e, \\text{MAD}$).<br/>' +
        '<b>Ý nghĩa phân tích:</b> Khi $n$ càng lớn ($n \\ge 30$), phổ điểm càng hội tụ về phân phối chuẩn và các chỉ số thống kê càng phản ánh chính xác năng lực thật của khóa học.',
      example:
        '<b>Ví dụ thực tế:</b> Khối đăng ký $N_{\\text{ĐK}} = 120$ học sinh, có $n_{\\text{vắng}} = 5$ em đánh dấu $x$. Khi đó $n = 120 - 5 = 115$ bài thi hợp lệ được đưa vào tính $\\bar{x}$ (không tính 5 em vắng thành điểm $0$).',
    },
    absent: {
      title: 'Thí sinh vắng thi (x)',
      symbol: 'n_{\\text{vắng}}',
      formula: '\\%\\text{Vắng} = \\dfrac{n_{\\text{vắng}}}{N_{\\text{ĐK}}} \\times 100\\%',
      meaning:
        '<b>Bản chất:</b> Tỷ lệ học sinh có tên trong danh sách lớp nhưng không có bài chấm (ký hiệu $x$).<br/>' +
        '<b>Ý nghĩa quản lý:</b> Phản ánh mức độ chuyên cần và kỷ luật thi cử. Nếu $\\%\\text{Vắng} > 10\\%$, mặt bằng điểm trung bình $\\bar{x}$ có thể bị <span class="hl-accent">sai lệch chọn lọc</span> (do học sinh yếu sợ thi nên nghỉ).',
      example:
        '<b>Ví dụ thực tế:</b> Lớp có $N_{\\text{ĐK}} = 50$ em, vắng $n_{\\text{vắng}} = 4$ em $\\Rightarrow \\%\\text{Vắng} = \\frac{4}{50}\\times 100\\% = 8.00\\%$. Giáo viên cần kiểm tra danh sách 4 em này để tổ chức thi bù.',
    },
    dtb: {
      title: 'Điểm trung bình cộng (Mean)',
      symbol: '\\bar{x}',
      formula: '\\bar{x} = \\dfrac{1}{n}\\sum_{i=1}^{n} x_i = \\dfrac{x_1 + x_2 + \\dots + x_n}{n}',
      meaning:
        '<b>Bản chất:</b> Là "trọng tâm khối lượng" của toàn bộ phổ điểm.<br/>' +
        '<b>Ý nghĩa phân tích điểm:</b><br/>' +
        '• Đánh giá mặt bằng chung của lớp/khối và độ khó đề thi ($\\bar{x} < 5.0$: đề khó hoặc hổng kiến thức; $6.0 \\le \\bar{x} \\le 7.2$: đề chuẩn phân hóa).<br/>' +
        '• <b>Lưu ý quan trọng:</b> $\\bar{x}$ rất nhạy cảm với <span class="hl-accent">điểm ngoại lai (Outliers)</span>. Do đó luôn phải đọc $\\bar{x}$ cặp đôi với <b>Trung vị $M_e$</b>:<br/>' +
        '&nbsp;&nbsp;+ Nếu $\\bar{x} < M_e$: Phổ lệch trái — có một số học sinh điểm rất thấp ($0 - 2$đ) kéo tụt ĐTB.<br/>' +
        '&nbsp;&nbsp;+ Nếu $\\bar{x} > M_e$: Phổ lệch phải — có một nhóm nhỏ học sinh xuất sắc ($9 - 10$đ) kéo ĐTB lên.',
      example:
        '<b>Ví dụ thống kê cụ thể:</b> Xét nhóm $n = 5$ học sinh có điểm: $\\{1.0;\\; 7.0;\\; 7.5;\\; 8.0;\\; 8.5\\}$.<br/>' +
        '• Tính $\\bar{x} = \\dfrac{1.0 + 7.0 + 7.5 + 8.0 + 8.5}{5} = \\mathbf{6.40}$ điểm.<br/>' +
        '• Dù $4/5$ học sinh đạt $\\ge 7.0$ (Khá/Giỏi), chỉ vì 1 bài $1.0$đ mà $\\bar{x}$ bị kéo xuống $6.40$ (trong khi Trung vị $M_e = 7.50$ phản ánh đúng thực lực nhóm hơn).',
    },
    median: {
      title: 'Trung vị (Median — Điểm giữa bảng)',
      symbol: 'M_e',
      formula:
        'M_e = \\begin{cases} x_{\\left(\\frac{n+1}{2}\\right)} & \\text{nếu } n \\text{ lẻ} \\\\[4pt] \\dfrac{1}{2}\\left(x_{\\left(\\frac{n}{2}\\right)} + x_{\\left(\\frac{n}{2}+1\\right)}\\right) & \\text{nếu } n \\text{ chẵn} \\end{cases}',
      meaning:
        '<b>Bản chất:</b> Mốc điểm chia đôi danh sách thí sinh sau khi sắp xếp tăng dần $x_{(1)} \\le x_{(2)} \\le \\dots \\le x_{(n)}$: đúng $50\\%$ học sinh có điểm $\\le M_e$ và $50\\%$ có điểm $\\ge M_e$.<br/>' +
        '<b>Ý nghĩa phân tích điểm:</b> Là chỉ số <b>bền vững (Robust)</b> phản ánh đúng thực lực của "học sinh đứng giữa lớp", hoàn toàn không bị bóp méo bởi vài bài điểm $0$ hay điểm $10$ cá biệt.',
      example:
        '<b>Ví dụ thống kê cụ thể:</b><br/>' +
        '• <b>TH1 ($n=5$ lẻ):</b> Điểm xếp tăng dần $\\{4.0;\\; 5.5;\\; \\mathbf{6.8};\\; 7.5;\\; 9.0\\} \\Rightarrow$ vị trí giữa là $x_{(3)} \\Rightarrow M_e = \\mathbf{6.80}$.<br/>' +
        '• <b>TH2 ($n=6$ chẵn):</b> $\\{4.0;\\; 5.5;\\; \\mathbf{6.8};\\; \\mathbf{7.2};\\; 8.0;\\; 9.0\\} \\Rightarrow M_e = \\dfrac{6.8 + 7.2}{2} = \\mathbf{7.00}$.',
    },
    dlc: {
      title: 'Độ lệch chuẩn (Standard Deviation)',
      symbol: '\\sigma',
      formula: '\\sigma = \\sqrt{\\dfrac{1}{n}\\sum_{i=1}^{n}\\left(x_i - \\bar{x}\\right)^2}',
      meaning:
        '<b>Bản chất:</b> Căn bậc hai của trung bình bình phương khoảng cách từ điểm mỗi học sinh $x_i$ đến ĐTB $\\bar{x}$. Vì lấy bình phương $(x_i - \\bar{x})^2$ nên các điểm lệch xa $\\bar{x}$ sẽ làm $\\sigma$ tăng vọt.<br/>' +
        '<b>Thước đo phân tích chất lượng lớp &amp; đề thi:</b><br/>' +
        '• $\\sigma < 1.0$: Điểm tụm очень sát quanh $\\bar{x}$ $\\Rightarrow$ học lực lớp rất đồng đều (hoặc đề thi thiếu câu phân loại).<br/>' +
        '• $1.1 \\le \\sigma \\le 1.7$: <b>Độ phân hóa chuẩn</b> của kỳ thi thử THPT, khoảng $68\\%$ học sinh nằm trong đoạn $[\\bar{x} - \\sigma,\\; \\bar{x} + \\sigma]$.<br/>' +
        '• $\\sigma > 2.0$: <span class="hl-accent">Phân cực quá mạnh</span> — lớp bị tách thành 2 cực Giỏi hẳn và Yếu kém hẳn, cần tách nhóm dạy phụ đạo.',
      example:
        '<b>Ví dụ so sánh 2 lớp có cùng ĐTB $\\bar{x} = 7.00$:</b><br/>' +
        '• <b>Lớp A:</b> $\\{6.5;\\; 6.8;\\; 7.0;\\; 7.2;\\; 7.5\\} \\Rightarrow \\sigma_A = \\mathbf{0.34}$ (Trình độ đồng đều, dễ dạy chung 1 giáo án).<br/>' +
        '• <b>Lớp B:</b> $\\{3.0;\\; 5.0;\\; 7.0;\\; 9.0;\\; 10.0\\} \\Rightarrow \\sigma_B = \\mathbf{2.61}$ (Chênh lệch cực lớn dù cùng $\\bar{x}=7.0$, bắt buộc phân tầng bài tập).',
    },
    mad: {
      title: 'Độ lệch tuyệt đối trung vị (MAD)',
      symbol: '\\text{MAD}',
      formula: '\\text{MAD} = \\text{Median}\\Big(\\big\\{\\,|x_i - M_e| \\;\\big|\\; i = 1,\\dots,n\\,\\big\\}\\Big)',
      meaning:
        '<b>Bản chất:</b> Là khoảng cách lệch "điển hình" của đa số học sinh trong lớp so với Trung vị $M_e$ ($50\\%$ học sinh có điểm nằm gọn trong khoảng $[M_e - \\text{MAD},\\; M_e + \\text{MAD}]$).<br/>' +
        '<b>Tại sao cần MAD bên cạnh ĐLC $\\sigma$?</b><br/>' +
        '• ĐLC $\\sigma$ dùng bình phương nên chỉ cần 1–2 học sinh nộp giấy trắng ($0$đ) là $\\sigma$ phình to giả tạo.<br/>' +
        '• $\\text{MAD}$ loại bỏ hoàn toàn nhiễu ngoại lai. <b>Mẹo chẩn đoán:</b> Nếu $\\sigma \\gg 1.5 \\times \\text{MAD}$ thì lớp thực chất học đều nhưng đang có một vài cá nhân điểm đột biến (cực thấp hoặc cực cao).',
      example:
        '<b>Ví dụ tính từng bước:</b> Xét 5 điểm $\\{2.0;\\; 6.5;\\; 7.0;\\; 7.2;\\; 7.5\\}$.<br/>' +
        '• <b>Bước 1:</b> Tìm Trung vị $M_e = \\mathbf{7.00}$.<br/>' +
        '• <b>Bước 2:</b> Tính độ lệch $|x_i - 7.0|$ cho từng em: $\\{5.0;\\; 0.5;\\; 0.0;\\; 0.2;\\; 0.5\\}$.<br/>' +
        '• <b>Bước 3:</b> Xếp tăng dần các độ lệch: $\\{0.0;\\; 0.2;\\; \\mathbf{0.5};\\; 0.5;\\; 5.0\\} \\Rightarrow \\text{MAD} = \\mathbf{0.50}$đ.<br/>' +
        '<i>Kết luận:</i> Đa số lớp chỉ lệch quanh mức $7.0 \\pm 0.5$đ (rất đều), còn $\\sigma = 2.04$ cao chỉ do duy nhất bài $2.0$đ gây ra!',
    },
    lt5: {
      title: 'Tỷ lệ dưới trung bình (< 5.0)',
      symbol: 'x_i < 5',
      formula: '\\%(x < 5) = \\dfrac{\\#\\big\\{x_i < 5.0\\big\\}}{n} \\times 100\\%',
      meaning:
        '<b>Bản chất:</b> Tỷ lệ học sinh chưa nắm vững kiến thức cơ bản (chưa đạt ngưỡng 5 điểm).<br/>' +
        '<b>Ý nghĩa phân tích:</b> Là chỉ báo rủi ro cần phụ đạo gấp. Nếu $\\%(x < 5) > 25\\%$, cần rà soát lại kiến thức nền tảng (mức Nhận biết – Thông hiểu) trước khi luyện đề nâng cao.',
      example:
        '<b>Ví dụ thực tế:</b> Khối có $n = 80$ thí sinh dự thi, trong đó có $12$ em đạt từ $1.5$ đến $4.8$ điểm $\\Rightarrow \\%(x < 5) = \\frac{12}{80} \\times 100\\% = \\mathbf{15.00\\%}$.',
    },
    gte7: {
      title: 'Tỷ lệ Khá – Giỏi (>= 7.0)',
      symbol: 'x_i \\ge 7',
      formula: '\\%(x \\ge 7) = \\dfrac{\\#\\big\\{x_i \\ge 7.0\\big\\}}{n} \\times 100\\%',
      meaning:
        '<b>Bản chất:</b> Tỷ lệ học sinh làm chủ tốt kiến thức và bắt đầu giải quyết được các câu hỏi Vận dụng.<br/>' +
        '<b>Ý nghĩa phân tích:</b> Dùng để đánh giá chất lượng mũi nhọn của từng giáo viên / từng khối và khả năng cạnh tranh xét tuyển Đại học của học sinh.',
      example:
        '<b>Ví dụ thực tế:</b> Trong $n = 80$ học sinh dự thi có $44$ em đạt từ $7.00$ đến $10.0$ điểm $\\Rightarrow \\%(x \\ge 7) = \\frac{44}{80} \\times 100\\% = \\mathbf{55.00\\%}$ (Nhóm lớp có chất lượng Khá – Giỏi tốt).',
    },
    mode: {
      title: 'Mốt của phân phối điểm (Mode — Đỉnh phổ điểm)',
      symbol: 'M_o',
      formula: 'M_o = \\arg\\max_{x} \\, f(x)',
      meaning:
        '<b>Bản chất:</b> Mức điểm cụ thể $x$ có tần số xuất hiện $f(x)$ nhiều nhất (cột cao nhất của phổ điểm).<br/>' +
        '<b>Ý nghĩa trong phân tích đề thi &amp; năng lực:</b><br/>' +
        '• Cho biết <b>"mức điểm phổ biến nhất"</b> mà phần đông học sinh chạm tới và dừng lại (ngưỡng trần năng lực đại trà).<br/>' +
        '• Nếu $M_o$ nằm ở $7.5 - 8.0$: Đề vừa sức, đa số học sinh giải tốt phần cơ bản và chỉ dừng ở câu Vận dụng cao.<br/>' +
        '• Nếu $M_o$ thấp ($4.0 - 5.0$) dù $\\bar{x}$ khá: Báo hiệu hiện tượng <b>phổ 2 đỉnh (Bimodal)</b> — đa số học sinh tụ ở mức trung bình yếu.',
      example:
        '<b>Ví dụ thống kê cụ thể:</b> Trong bảng điểm 40 học sinh:<br/>' +
        '• Mức $7.50$đ có <b>9 học sinh</b> đạt được (nhiều nhất lớp).<br/>' +
        '• Mức $8.00$đ có 6 học sinh; mức $6.50$đ có 5 học sinh.<br/>' +
        '$\\Rightarrow \\text{Mode } M_o = \\mathbf{7.50}\\text{ (9 TS)}$. Nghĩa là mốc $7.50$đ là "điểm rơi" phổ biến nhất của đề thi này.',
    },
    score10: {
      title: 'Số lượng điểm tuyệt đối (Điểm 10)',
      symbol: 'x_i = 10',
      formula: '\\%(x = 10) = \\dfrac{\\#\\big\\{x_i = 10.0\\big\\}}{n} \\times 100\\%',
      meaning:
        '<b>Bản chất:</b> Số lượng và tỷ lệ học sinh chinh phục trọn vẹn 100% câu hỏi (bao gồm cả câu Vận dụng cao lấy điểm 10).<br/>' +
        '<b>Ý nghĩa phân tích:</b> Đo lường hiệu quả bồi dưỡng học sinh giỏi xuất sắc và kiểm tra xem câu cuối của đề thi có bị quá dễ (mưa điểm 10) hay quá đánh đố hay không.',
      example:
        '<b>Ví dụ thực tế:</b> Cả khối $n = 200$ thí sinh có $3$ em đạt $10.0$ $\\Rightarrow \\%(x=10) = 1.50\\%$ (Đề phân loại tốt nhóm dẫn đầu).',
    },
    score0: {
      title: 'Số lượng Điểm 0',
      symbol: 'x_i = 0',
      formula: 'n_0 = \\#\\big\\{x_i = 0.0\\big\\}',
      meaning:
        '<b>Bản chất:</b> Thí sinh có mặt phòng thi nhưng đạt $0.0$ điểm (nộp giấy trắng, tô sai mã đề/SBD hoặc mất gốc hoàn toàn).<br/>' +
        '<b>Lưu ý:</b> Hệ thống tách bạch rõ: học sinh nghỉ thi ($x$) được tính vào <b>Vắng thi</b>, chỉ học sinh đi thi mà $0$ điểm mới tính vào $n_0$.',
      example:
        '<b>Ví dụ thực tế:</b> Nếu $n_0 = 1$, giáo viên cần kiểm tra ngay bài làm của học sinh đó xem do lỗi kỹ thuật tô phiếu hay do hổng kiến thức.',
    },
    lte1: {
      title: 'Ngưỡng điểm liệt (<= 1.0)',
      symbol: 'x_i \\le 1',
      formula: '\\%(x \\le 1) = \\dfrac{\\#\\big\\{x_i \\le 1.0\\big\\}}{n} \\times 100\\%',
      meaning:
        '<b>Bản chất:</b> Theo quy chế thi Tốt nghiệp THPT của Bộ GD&amp;ĐT, bài thi độc lập hoặc môn thành phần có điểm $x_i \\le 1.0$ là <b>Điểm liệt</b> (không đủ điều kiện xét tốt nghiệp).<br/>' +
        '<b>Ý nghĩa cảnh báo:</b> Là nhóm học sinh báo động đỏ cần kèm cặp sát sao nhất tại trung tâm.',
      example:
        '<b>Ví dụ thực tế:</b> Nếu khối có $2$ học sinh đạt $0.75$đ và $1.00$đ trên $n=100$ thí sinh $\\Rightarrow \\%(x \\le 1) = 2.00\\%$ (Cần cảnh báo phụ huynh &amp; giáo viên phụ trách).',
    },
  };

  function renderLatexFormula(tex, displayMode = false) {
    if (window.katex && typeof window.katex.renderToString === 'function') {
      try {
        return window.katex.renderToString(tex, {
          displayMode,
          throwOnError: false,
        });
      } catch (e) {
        return `<code>${escapeHtml(tex)}</code>`;
      }
    }
    return `<code>${escapeHtml(tex)}</code>`;
  }

  function renderTextWithInlineLatex(text) {
    return String(text || '').replace(/\$([^$]+)\$/g, (_, math) => renderLatexFormula(math, false));
  }

  function setupStatTableLatexTooltips() {
    const tooltip = document.getElementById('statLatexTooltip');
    if (!tooltip) return;

    let activeRow = null;

    function anchorTooltipToLeftOfRow(row) {
      if (!row) return;
      const rowRect = row.getBoundingClientRect();
      const pad = 10;
      const tw = tooltip.offsetWidth || 480;
      const th = tooltip.offsetHeight || 260;

      // Always place immediately to the LEFT of the hovered row
      let left = rowRect.left - tw - 12;
      if (left < pad) {
        left = pad;
      }
      let top = rowRect.top + rowRect.height / 2 - th / 2;
      top = Math.max(pad, Math.min(window.innerHeight - th - pad, top));

      tooltip.style.left = `${Math.round(left)}px`;
      tooltip.style.top = `${Math.round(top)}px`;
    }

    document.addEventListener('mouseover', (e) => {
      const row = e.target.closest('#thptStatsTable tr[data-stat-key]');
      if (!row) return;
      if (row === activeRow && tooltip.classList.contains('visible')) return;

      const key = row.getAttribute('data-stat-key');
      const info = STAT_LATEX_EXPLANATIONS[key];
      if (!info) return;

      activeRow = row;
      tooltip.innerHTML = `
        <div class="stat-latex-header">
          <span>${escapeHtml(info.title)}</span>
          <span class="stat-symbol-pill">${renderLatexFormula(info.symbol, false)}</span>
        </div>
        <div class="stat-latex-formula-box">
          ${renderLatexFormula(info.formula, true)}
        </div>
        <div class="stat-latex-body">
          <div class="stat-latex-section">
            <div class="stat-latex-sec-title"><i class="fa-solid fa-magnifying-glass-chart"></i> Ý nghĩa phân tích chuyên môn</div>
            <div>${renderTextWithInlineLatex(info.meaning || info.desc || '')}</div>
          </div>
          ${
            info.example
              ? `<div class="stat-latex-example-box">
                  <div class="stat-latex-sec-title"><i class="fa-solid fa-calculator"></i> Ví dụ thực tế trong thống kê điểm</div>
                  <div>${renderTextWithInlineLatex(info.example)}</div>
                </div>`
              : ''
          }
        </div>
      `;
      tooltip.classList.add('visible');
      anchorTooltipToLeftOfRow(row);
    });

    document.addEventListener('mouseout', (e) => {
      const row = e.target.closest('#thptStatsTable tr[data-stat-key]');
      if (row && !row.contains(e.relatedTarget)) {
        activeRow = null;
        tooltip.classList.remove('visible');
      }
    });

    window.addEventListener(
      'scroll',
      () => {
        if (activeRow && tooltip.classList.contains('visible')) {
          anchorTooltipToLeftOfRow(activeRow);
        }
      },
      { passive: true }
    );
  }

  // ============================================================================
  // MODERN EDTECH / FINTECH CANVAS CHART ENGINE
  // ============================================================================
  function drawRoundedTopRect(ctx, x, y, w, h, r) {
    if (h <= 0) return;
    const radius = Math.min(r, w / 2, h);
    ctx.beginPath();
    ctx.moveTo(x, y + h);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.lineTo(x + w - radius, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + radius);
    ctx.lineTo(x + w, y + h);
    ctx.closePath();
    ctx.fill();
  }

  function drawRoundedBadge(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
    ctx.fill();
  }

  let sharedMeasureCtx = null;
  function getSharedMeasureCtx() {
    if (!sharedMeasureCtx) {
      sharedMeasureCtx = document.createElement('canvas').getContext('2d');
    }
    return sharedMeasureCtx;
  }

  function createSvgChartContext(canvas, width, height) {
    const parent = canvas.parentElement;
    canvas.style.display = 'none';
    let svg = parent.querySelector('svg.thpt-vector-svg');
    if (!svg) {
      svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('class', 'thpt-vector-svg');
      svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
      parent.insertBefore(svg, canvas);
    }
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');

    const elements = [];
    let currentPath = [];
    const stateStack = [];
    let st = {
      fillStyle: '#000000',
      strokeStyle: '#000000',
      lineWidth: 1,
      lineJoin: 'miter',
      lineCap: 'butt',
      globalAlpha: 1,
      font: '12px Inter, sans-serif',
      textAlign: 'left',
      textBaseline: 'alphabetic',
      lineDash: [],
      transforms: [],
    };

    const fmtN = (n) => Math.round(n * 100) / 100;

    function buildTransformAttr() {
      if (!st.transforms.length) return '';
      return ` transform="${st.transforms.join(' ')}"`;
    }

    function buildAlphaAttr() {
      if (st.globalAlpha >= 0.999) return '';
      return ` opacity="${fmtN(st.globalAlpha)}"`;
    }

    return {
      get fillStyle() { return st.fillStyle; },
      set fillStyle(v) { st.fillStyle = v; },
      get strokeStyle() { return st.strokeStyle; },
      set strokeStyle(v) { st.strokeStyle = v; },
      get lineWidth() { return st.lineWidth; },
      set lineWidth(v) { st.lineWidth = v; },
      get lineJoin() { return st.lineJoin; },
      set lineJoin(v) { st.lineJoin = v; },
      get lineCap() { return st.lineCap; },
      set lineCap(v) { st.lineCap = v; },
      get globalAlpha() { return st.globalAlpha; },
      set globalAlpha(v) { st.globalAlpha = v; },
      get font() { return st.font; },
      set font(v) { st.font = v; },
      get textAlign() { return st.textAlign; },
      set textAlign(v) { st.textAlign = v; },
      get textBaseline() { return st.textBaseline; },
      set textBaseline(v) { st.textBaseline = v; },

      save() {
        stateStack.push({
          ...st,
          lineDash: st.lineDash.slice(),
          transforms: st.transforms.slice(),
        });
      },
      restore() {
        if (stateStack.length > 0) {
          st = stateStack.pop();
        }
      },
      scale(sx, sy) {
        if (Math.abs(sx - 1) > 1e-4 || Math.abs(sy - 1) > 1e-4) {
          st.transforms.push(`scale(${fmtN(sx)}, ${fmtN(sy)})`);
        }
      },
      translate(tx, ty) {
        st.transforms.push(`translate(${fmtN(tx)}, ${fmtN(ty)})`);
      },
      rotate(rad) {
        const deg = (rad * 180) / Math.PI;
        st.transforms.push(`rotate(${fmtN(deg)})`);
      },
      setLineDash(arr) {
        st.lineDash = Array.isArray(arr) ? arr.slice() : [];
      },
      beginPath() {
        currentPath = [];
      },
      moveTo(x, y) {
        currentPath.push(`M ${fmtN(x)} ${fmtN(y)}`);
      },
      lineTo(x, y) {
        currentPath.push(`L ${fmtN(x)} ${fmtN(y)}`);
      },
      quadraticCurveTo(cpx, cpy, x, y) {
        currentPath.push(`Q ${fmtN(cpx)} ${fmtN(cpy)} ${fmtN(x)} ${fmtN(y)}`);
      },
      closePath() {
        currentPath.push('Z');
      },
      fill() {
        if (!currentPath.length) return;
        elements.push(
          `<path d="${currentPath.join(' ')}" fill="${escapeHtml(st.fillStyle)}"${buildAlphaAttr()}${buildTransformAttr()}/>`
        );
      },
      stroke() {
        if (!currentPath.length) return;
        const dashAttr = st.lineDash.length ? ` stroke-dasharray="${st.lineDash.join(',')}"` : '';
        const capAttr = st.lineCap !== 'butt' ? ` stroke-linecap="${st.lineCap}"` : '';
        const joinAttr = st.lineJoin !== 'miter' ? ` stroke-linejoin="${st.lineJoin}"` : '';
        elements.push(
          `<path d="${currentPath.join(' ')}" fill="none" stroke="${escapeHtml(st.strokeStyle)}" stroke-width="${fmtN(st.lineWidth)}"${dashAttr}${capAttr}${joinAttr}${buildAlphaAttr()}${buildTransformAttr()}/>`
        );
      },
      fillRect(x, y, w, h) {
        elements.push(
          `<rect x="${fmtN(x)}" y="${fmtN(y)}" width="${fmtN(w)}" height="${fmtN(h)}" fill="${escapeHtml(st.fillStyle)}"${buildAlphaAttr()}${buildTransformAttr()}/>`
        );
      },
      strokeRect(x, y, w, h) {
        const dashAttr = st.lineDash.length ? ` stroke-dasharray="${st.lineDash.join(',')}"` : '';
        elements.push(
          `<rect x="${fmtN(x)}" y="${fmtN(y)}" width="${fmtN(w)}" height="${fmtN(h)}" fill="none" stroke="${escapeHtml(st.strokeStyle)}" stroke-width="${fmtN(st.lineWidth)}"${dashAttr}${buildAlphaAttr()}${buildTransformAttr()}/>`
        );
      },
      fillText(text, x, y) {
        let anchor = 'start';
        if (st.textAlign === 'center') anchor = 'middle';
        else if (st.textAlign === 'right' || st.textAlign === 'end') anchor = 'end';

        let dyAttr = '';
        if (st.textBaseline === 'middle') dyAttr = ' dy="0.35em"';
        else if (st.textBaseline === 'bottom') dyAttr = ' dy="-0.12em"';
        else if (st.textBaseline === 'top') dyAttr = ' dy="0.85em"';

        elements.push(
          `<text x="${fmtN(x)}" y="${fmtN(y)}" fill="${escapeHtml(st.fillStyle)}" text-anchor="${anchor}"${dyAttr} style="font: ${escapeHtml(st.font)}; user-select: none;"${buildAlphaAttr()}${buildTransformAttr()}>${escapeHtml(text)}</text>`
        );
      },
      measureText(text) {
        const mCtx = getSharedMeasureCtx();
        mCtx.font = st.font;
        return mCtx.measureText(text);
      },
      commitSvg() {
        svg.innerHTML = elements.join('');
      },
    };
  }

  function triggerChartAnimation(stats) {
    if (state.chartAnimFrameId) cancelAnimationFrame(state.chartAnimFrameId);
    const startTime = performance.now();
    const duration = 680;

    function animateFrame(now) {
      const t = Math.min(1, (now - startTime) / duration);
      state.chartAnimProgress = 1 - Math.pow(1 - t, 3);
      drawTHPTChartOnCanvas(document.getElementById('phoDiemCanvas'), stats, state.chartAnimProgress, -1);
      if (t < 1) {
        state.chartAnimFrameId = requestAnimationFrame(animateFrame);
      }
    }
    state.chartAnimFrameId = requestAnimationFrame(animateFrame);
  }

  function drawTHPTChartOnCanvas(canvas, stats, animProgress = 1, hoverIndex = -1, customDims = null) {
    if (!canvas || !stats) return;
    const dpr = customDims ? customDims.scale : 1;
    const width = customDims ? customDims.width : canvas.parentElement.clientWidth || 760;
    const height = customDims ? customDims.height : canvas.parentElement.clientHeight || 410;

    if (customDims) {
      if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
        canvas.width = Math.round(width * dpr);
        canvas.height = Math.round(height * dpr);
      }
    }

    const ctx = customDims ? canvas.getContext('2d') : createSvgChartContext(canvas, width, height);
    ctx.save();
    ctx.scale(dpr, dpr);

    // Clean white canvas
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);

    const isCompactMobile = !customDims && width < 580;
    const padTop = isCompactMobile ? 62 : 52;
    const padBottom = isCompactMobile ? 50 : 60;
    const padLeft = isCompactMobile ? 32 : 48;
    const padRight = isCompactMobile ? 10 : 20;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    // Header & Legend inside chart
    const sess = getCurrentSession();
    const gradeText = customDims?.gradeOverride || state.filterGrade;
    const subjText = customDims?.subjectOverride || state.currentSubject;
    const teacherText =
      (customDims ? customDims.teacherOverride : state.filterTeacher) !== 'ALL'
        ? ` • GV ${customDims ? customDims.teacherOverride : state.filterTeacher}`
        : '';

    ctx.fillStyle = '#27397c';
    ctx.font = isCompactMobile ? '800 12px Inter, sans-serif' : '800 14.5px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText(
      `Phân bố điểm Môn ${subjText} — Khối ${gradeText}${teacherText}`,
      padLeft,
      isCompactMobile ? 14 : 18
    );

    // Color legend pills (Strictly 2-color palette: #27397c & #ee642c)
    const legendItems = [
      { label: 'Dưới TB (<5)', color: '#ee642c' },
      { label: 'Từ 5.0 trở lên (>=5)', color: '#27397c' },
    ];
    if (isCompactMobile) {
      let lx = padLeft;
      const ly = 34;
      for (let i = 0; i < legendItems.length; i++) {
        const item = legendItems[i];
        ctx.fillStyle = item.color;
        drawRoundedBadge(ctx, lx, ly - 4.5, 9, 9, 2.5);
        lx += 12;
        ctx.font = '600 10px Inter, sans-serif';
        ctx.fillStyle = '#475569';
        ctx.textAlign = 'left';
        ctx.fillText(item.label, lx, ly);
        lx += ctx.measureText(item.label).width + 12;
      }
    } else {
      let lx = width - padRight;
      for (let i = legendItems.length - 1; i >= 0; i--) {
        const item = legendItems[i];
        ctx.font = '600 11px Inter, sans-serif';
        const tw = ctx.measureText(item.label).width;
        lx -= tw;
        ctx.fillStyle = '#475569';
        ctx.textAlign = 'left';
        ctx.fillText(item.label, lx, 18);
        lx -= 14;
        ctx.fillStyle = item.color;
        drawRoundedBadge(ctx, lx, 13, 10, 10, 3);
        lx -= 14;
      }
    }

    const rawMax = Math.max(stats.maxBinCount, 1);
    const niceMax = computeNiceYMax(rawMax * 1.22);
    const numYTicks = 5;
    const yStep = niceMax / numYTicks;

    // Subtle dashed horizontal gridlines
    ctx.font = '600 11px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';

    for (let i = 0; i <= numYTicks; i++) {
      const val = Math.round(i * yStep);
      const y = padTop + plotH - (val / niceMax) * plotH;

      ctx.strokeStyle = i === 0 ? '#cbd5e1' : '#f1f5f9';
      ctx.lineWidth = i === 0 ? 1.5 : 1;
      if (i > 0) ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(padLeft + plotW, y);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = '#64748b';
      ctx.fillText(String(val), padLeft - 10, y);
    }

    const bins = stats.bins;
    const numBins = bins.length;
    const slotW = plotW / numBins;
    const barW = Math.max(4, Math.min(34, slotW * 0.68));

    if (!customDims) state.chartBarRects = [];

    // Draw Solid Rounded Bars (Strictly 2-color palette: #ee642c & #27397c)
    for (let i = 0; i < numBins; i++) {
      const bin = bins[i];
      const barDelay = (i / numBins) * 0.22;
      const localProgress = Math.max(0, Math.min(1, (animProgress - barDelay) / (1 - barDelay)));

      const fullBarH = (bin.count / niceMax) * plotH;
      const barH = fullBarH * localProgress;
      const x = padLeft + i * slotW + (slotW - barW) / 2;
      const y = padTop + plotH - barH;
      const centerX = padLeft + i * slotW + slotW / 2;

      // Hover or selected column highlight background
      const isSelected = !customDims && state.selectedBinIndex === i;
      if (i === hoverIndex || isSelected) {
        ctx.fillStyle = isSelected ? 'rgba(39, 57, 124, 0.14)' : 'rgba(39, 57, 124, 0.08)';
        drawRoundedBadge(ctx, padLeft + i * slotW + 2, padTop, slotW - 4, plotH, 6);
      }

      // Solid color by score range (2 colors only: #ee642c for <5, #27397c for >=5)
      if (bin.high <= 5.001) {
        ctx.fillStyle = '#ee642c';
      } else {
        ctx.fillStyle = '#27397c';
      }

      if (barH > 0.5) {
        drawRoundedTopRect(ctx, x, y, barW, barH, numBins >= 45 ? 3 : 6);
        if (isSelected) {
          ctx.strokeStyle = '#ee642c';
          ctx.lineWidth = 2;
          ctx.strokeRect(x, y, barW, barH);
        }
      } else {
        ctx.fillStyle = '#e2e8f0';
        ctx.fillRect(x, padTop + plotH - 2, barW, 2);
      }

      if (!customDims) {
        state.chartBarRects.push({
          index: i,
          x: padLeft + i * slotW,
          y: padTop,
          w: slotW,
          h: plotH,
          barX: centerX,
          barTopY: padTop + plotH - fullBarH,
          bin,
        });
      }

      // Horizontal Count Badge above bar
      if (localProgress > 0.5 && bin.count > 0) {
        ctx.fillStyle = i === hoverIndex ? '#ee642c' : '#27397c';
        ctx.font =
          numBins >= 45
            ? '700 8px Inter, sans-serif'
            : numBins > 25
            ? '700 9.5px Inter, sans-serif'
            : '700 11px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(String(bin.count), centerX, y - 4);
      }

      // Clean Angled X-axis label
      ctx.save();
      ctx.translate(centerX, padTop + plotH + 10);
      ctx.rotate(numBins >= 45 ? -Math.PI / 3.1 : -Math.PI / 4.2);
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = i === hoverIndex ? '#ee642c' : '#475569';
      ctx.font =
        numBins >= 45
          ? '600 7.5px Inter, sans-serif'
          : numBins > 25
          ? '600 9px Inter, sans-serif'
          : '600 10.5px Inter, sans-serif';
      ctx.fillText(bin.shortLabel, 0, 0);
      ctx.restore();
    }

    // Data-Faithful Smoothed Trend Curve (KDE over actual bins) & Floating ĐTB Badge
    if (state.showBellCurve && stats.count > 1 && animProgress > 0.3) {
      const curveAlpha = Math.min(1, (animProgress - 0.3) / 0.7);
      ctx.save();
      ctx.globalAlpha = curveAlpha;

      const trendPts = computeTrendCurvePoints(bins, padLeft, plotW, padTop, plotH, niceMax, state.binStep);

      ctx.strokeStyle = '#ee642c';
      ctx.lineWidth = 2.4;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.beginPath();
      trendPts.forEach((pt, idx) => {
        if (idx === 0) ctx.moveTo(pt.x, pt.y);
        else ctx.lineTo(pt.x, pt.y);
      });
      ctx.stroke();

      // Mean Reference Line + Pill Tag
      const meanX = padLeft + (stats.mean / 10) * plotW;
      ctx.strokeStyle = '#ee642c';
      ctx.lineWidth = 1.6;
      ctx.setLineDash([5, 4]);
      ctx.beginPath();
      ctx.moveTo(meanX, padTop + 18);
      ctx.lineTo(meanX, padTop + plotH);
      ctx.stroke();
      ctx.setLineDash([]);

      const badgeText = `ĐTB: ${fmtFixed(stats.mean, 2)}`;
      ctx.font = '700 11px Inter, sans-serif';
      const bw = ctx.measureText(badgeText).width + 14;
      const bx = Math.max(padLeft, Math.min(padLeft + plotW - bw, meanX - bw / 2));
      ctx.fillStyle = '#fef2ec';
      drawRoundedBadge(ctx, bx, padTop - 2, bw, 20, 6);
      ctx.fillStyle = '#ee642c';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(badgeText, bx + bw / 2, padTop + 8);

      ctx.restore();
    }

    ctx.restore();
    if (ctx.commitSvg) ctx.commitSvg();
  }

  function computeTrendCurvePoints(bins, padLeft, plotW, padTop, plotH, niceMax, binStep) {
    const B = bins.length;
    if (B === 0) return [];
    const counts = bins.map((b) => b.count);
    const maxCount = Math.max(...counts, 0);
    if (maxCount === 0) return [];

    const sigma = Math.max(0.72, 0.41 / (binStep || 0.5));
    const twoSigmaSq = 2 * sigma * sigma;

    function evalRawKernel(u) {
      let num = 0;
      let den = 0;
      for (let j = -2; j <= B + 1; j++) {
        const yj = j >= 0 && j < B ? counts[j] : 0;
        const d = u - j;
        const w = Math.exp(-(d * d) / twoSigmaSq);
        num += yj * w;
        den += w;
      }
      return den > 0 ? num / den : 0;
    }

    let maxSmoothed = 0;
    for (let i = 0; i < B; i++) {
      const v = evalRawKernel(i);
      if (v > maxSmoothed) maxSmoothed = v;
    }
    const peakScale = maxSmoothed > 0 ? Math.min(1.24, (maxCount * 0.90) / maxSmoothed) : 1;

    const steps = 160;
    const pts = [];
    for (let s = 0; s <= steps; s++) {
      const frac = s / steps;
      const cx = padLeft + frac * plotW;
      const u = frac * B - 0.5;
      const val = Math.max(0, evalRawKernel(u) * peakScale);
      const cy = Math.max(padTop + 6, padTop + plotH - (val / niceMax) * plotH);
      pts.push({ x: cx, y: cy });
    }
    return pts;
  }

  function computeNiceYMax(target) {
    if (target <= 5) return 5;
    if (target <= 10) return 10;
    const magnitude = Math.pow(10, Math.floor(Math.log10(target)));
    const residual = target / magnitude;
    let niceRes;
    if (residual <= 1.2) niceRes = 1.2;
    else if (residual <= 1.5) niceRes = 1.5;
    else if (residual <= 2) niceRes = 2;
    else if (residual <= 2.5) niceRes = 2.5;
    else if (residual <= 3) niceRes = 3;
    else if (residual <= 4) niceRes = 4;
    else if (residual <= 5) niceRes = 5;
    else if (residual <= 6) niceRes = 6;
    else if (residual <= 8) niceRes = 8;
    else niceRes = 10;
    return Math.ceil(niceRes * magnitude);
  }

  function setupMainChartInteractivity() {
    const canvas = document.getElementById('phoDiemCanvas');
    const wrap = document.getElementById('mainChartWrap') || canvas?.parentElement;
    const tooltip = document.getElementById('chartTooltip');
    if (!canvas || !wrap || !tooltip) return;

    let lastHoverIndex = -1;

    wrap.addEventListener('mousemove', (e) => {
      const rect = wrap.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      let found = null;
      for (let i = 0; i < state.chartBarRects.length; i++) {
        const b = state.chartBarRects[i];
        if (mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h) {
          found = b;
          break;
        }
      }

      const newHoverIdx = found ? found.index : -1;
      if (newHoverIdx !== lastHoverIndex) {
        lastHoverIndex = newHoverIdx;
        const sess = getCurrentSession();
        const records = getFilteredRecords(sess, state.currentSubject, state.filterTeacher, state.filterGrade);
        const stats = computeStatistics(records, state.binStep);
        drawTHPTChartOnCanvas(canvas, stats, 1, newHoverIdx);
      }

      if (found) {
        wrap.style.cursor = 'pointer';
        tooltip.classList.add('visible');
        tooltip.style.left = `${found.barX}px`;
        tooltip.style.top = `${Math.max(42, found.barTopY)}px`;
        tooltip.innerHTML = `<div style="font-weight:800; color:#fbd5c4;">Khoảng điểm ${found.bin.label}</div><div>Số lượng: <b>${fmtInt(found.bin.count)} TS</b> (${fmtFixed(found.bin.pct, 1)}%)</div><div style="font-size:11px; color:#ee642c; margin-top:3px;">👆 Bấm vào cột để xem danh sách HS</div>`;
      } else {
        wrap.style.cursor = 'default';
        tooltip.classList.remove('visible');
      }
    });

    wrap.addEventListener('mouseleave', () => {
      wrap.style.cursor = 'default';
      tooltip.classList.remove('visible');
      if (lastHoverIndex !== -1) {
        lastHoverIndex = -1;
        const sess = getCurrentSession();
        const records = getFilteredRecords(sess, state.currentSubject, state.filterTeacher, state.filterGrade);
        const stats = computeStatistics(records, state.binStep);
        drawTHPTChartOnCanvas(canvas, stats, 1, -1);
      }
    });

    wrap.addEventListener('click', (e) => {
      const rect = wrap.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      let found = null;
      for (let i = 0; i < state.chartBarRects.length; i++) {
        const b = state.chartBarRects[i];
        if (mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h) {
          found = b;
          break;
        }
      }

      if (!found) return;

      state.selectedBinIndex = found.index;
      const sess = getCurrentSession();
      const records = getFilteredRecords(sess, state.currentSubject, state.filterTeacher, state.filterGrade);
      const stats = computeStatistics(records, state.binStep);

      drawTHPTChartOnCanvas(canvas, stats, 1, found.index);
      renderSelectedBinInlinePanel(stats);
      openBinStudentsModal(stats, found.index, state.currentSubject, state.filterGrade, state.filterTeacher, sess);
    });
  }

  function getStudentHighlightMeta(score, isAbsent = false) {
    if (isAbsent || score === null || score === undefined || isNaN(score)) {
      return {
        rowClass: '',
        nameClass: '',
        nameTagHtml: '',
        scoreClass: 'score-absent',
      };
    }
    if (score < 5) {
      return {
        rowClass: 'row-student-lt5',
        nameClass: 'student-name-lt5',
        nameTagHtml: `<span class="student-tier-tag tag-lt5">Dưới 5</span>`,
        scoreClass: 'score-lt5',
      };
    }
    if (score >= 9) {
      const is10 = Math.abs(score - 10) < 1e-9;
      return {
        rowClass: 'row-student-gt9',
        nameClass: 'student-name-gt9',
        nameTagHtml: is10
          ? `<span class="student-tier-tag tag-10">Điểm 10</span>`
          : `<span class="student-tier-tag tag-gt9">Trên 9</span>`,
        scoreClass: is10 ? 'score-10' : 'score-gt9',
      };
    }
    return {
      rowClass: '',
      nameClass: '',
      nameTagHtml: '',
      scoreClass: score >= 8 ? 'score-high' : 'score-mid',
    };
  }

  function buildStudentRowsHtml(students, sessionDate) {
    if (!students || students.length === 0) {
      return `<tr><td colspan="6" style="text-align:center; padding:18px; color:#64748b; font-weight:600;">Không có học sinh nào có điểm trong cột này</td></tr>`;
    }
    return students
      .map((item, idx) => {
        const hl = getStudentHighlightMeta(item.score, item.absent);

        return `
          <tr class="${hl.rowClass}">
            <td class="stt-col">${idx + 1}</td>
            <td class="${hl.nameClass}" style="font-weight:700;">${escapeHtml(item.name)}${hl.nameTagHtml}</td>
            <td class="num-col">Khối ${escapeHtml(String(item.grade))}</td>
            <td class="num-col">GV ${escapeHtml(item.teacher)}</td>
            <td class="num-col">${escapeHtml(item.examDate || sessionDate || '-')}</td>
            <td class="num-col"><span class="score-pill-badge ${hl.scoreClass}">${fmtFixed(item.score, 2)}</span></td>
          </tr>
        `;
      })
      .join('');
  }

  function buildTeacherSummaryBadgesHtml(students) {
    if (!students || students.length === 0) {
      return `<span class="mini-stat-chip" style="opacity:0.65;"><i class="fa-solid fa-chalkboard-user"></i> Không có học sinh trong cột điểm này</span>`;
    }
    const map = new Map();
    students.forEach((s) => {
      const t = s.teacher || 'Chưa rõ';
      map.set(t, (map.get(t) || 0) + 1);
    });
    const parts = [];
    map.forEach((cnt, t) => {
      parts.push(
        `<span class="mini-stat-chip"><i class="fa-solid fa-chalkboard-user"></i> ${escapeHtml(t)}: <b>${cnt}</b></span>`
      );
    });
    return parts.join('');
  }

  function renderSelectedBinInlinePanel() {
    const panel = document.getElementById('selectedBinStudentsPanel');
    if (panel) {
      panel.style.display = 'none';
      panel.innerHTML = '';
    }
  }

  function closeBinStudentsModal() {
    const modal = document.getElementById('binStudentsModal');
    if (modal) modal.classList.remove('open');
    state.selectedBinIndex = null;
    renderSelectedBinInlinePanel();
    const canvas = document.getElementById('phoDiemCanvas');
    if (canvas) {
      const sess = getCurrentSession();
      const records = getFilteredRecords(sess, state.currentSubject, state.filterTeacher, state.filterGrade);
      const stats = computeStatistics(records, state.binStep);
      drawTHPTChartOnCanvas(canvas, stats, 1, -1);
    }
  }

  function openBinStudentsModal(stats, binIndex, subject, grade, teacherFilter, session) {
    const modal = document.getElementById('binStudentsModal');
    if (!modal || !stats || !stats.bins || !stats.bins[binIndex]) return;

    const bin = stats.bins[binIndex];
    const teacherLabel = teacherFilter && teacherFilter !== 'ALL' ? ` • GV ${teacherFilter}` : ' • Cả nhóm';

    document.getElementById('binModalTitle').innerHTML =
      `<i class="fa-solid fa-users-viewfinder" style="color:#27397c; margin-right:6px;"></i>CỘT ĐIỂM <span style="color:#ee642c;">${escapeHtml(bin.shortLabel)}</span> <span style="font-size:13px; color:#475569;">(${escapeHtml(bin.label)})</span>`;

    document.getElementById('binModalSubtitle').innerHTML =
      `<b>${escapeHtml(subject)}</b> • Khối <b>${escapeHtml(String(grade))}</b>${escapeHtml(teacherLabel)} • <b style="color:#ee642c;">${fmtInt(bin.count)} TS</b> (${fmtFixed(bin.pct, 1)}%)`;

    // Render quick switcher pills for all columns
    const switcher = document.getElementById('binModalQuickSwitcher');
    if (switcher) {
      switcher.innerHTML =
        `<span style="font-size:11.5px; font-weight:700; color:#27397c; display:inline-flex; align-items:center; gap:4px; margin-right:4px;"><i class="fa-solid fa-chart-column"></i> Cột:</span>` +
        stats.bins
          .map((b, idx) => {
            const act = idx === binIndex ? 'active' : '';
            const dimStyle = b.count === 0 && idx !== binIndex ? 'opacity:0.45;' : '';
            return `<button type="button" class="bin-switch-pill ${act}" style="${dimStyle}" data-modal-bin="${idx}">${escapeHtml(b.shortLabel)} (${b.count})</button>`;
          })
          .join('');

      switcher.querySelectorAll('[data-modal-bin]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const newIdx = parseInt(btn.getAttribute('data-modal-bin'), 10);
          if (subject === state.currentSubject && String(grade) === String(state.filterGrade)) {
            state.selectedBinIndex = newIdx;
            drawTHPTChartOnCanvas(document.getElementById('phoDiemCanvas'), stats, 1, newIdx);
          }
          openBinStudentsModal(stats, newIdx, subject, grade, teacherFilter, session);
        });
      });
    }

    document.getElementById('binModalTeacherSummary').innerHTML = buildTeacherSummaryBadgesHtml(bin.students);
    document.getElementById('binModalTableBody').innerHTML = buildStudentRowsHtml(bin.students, session?.date);

    modal.classList.add('open');
  }

  // ============================================================================
  // SECTION 2: MULTI-SESSION COMPARISON (Scoped to Current Subject & Grade)
  // ============================================================================
  function renderMultiSessionComparison() {
    const subj = state.currentSubject;
    const grade = state.filterGrade;
    const teacherSuffix = state.filterTeacher !== 'ALL' ? ` • GV ${state.filterTeacher}` : '';
    document.getElementById('comparisonBannerTitle').textContent =
      `${subj.toUpperCase()} — KHỐI ${grade}${teacherSuffix.toUpperCase()} QUA CÁC ĐỢT THI`;

    const sessionStatsList = state.sessions.map((sess) => {
      const recs = getFilteredRecords(sess, subj, state.filterTeacher, grade);
      return {
        session: sess,
        stats: computeStatistics(recs, 0.5),
      };
    });

    const table = document.getElementById('multiSessionComparisonTable');
    if (!table) return;

    let theadHtml = `<thead><tr><th>CHỈ SỐ (KHỐI ${escapeHtml(String(grade))})</th>`;
    sessionStatsList.forEach((item) => {
      theadHtml += `<th colspan="2">${escapeHtml(item.session.shortName || item.session.name)}</th>`;
    });
    theadHtml += `</tr></thead>`;

    const rowsConfig = [
      {
        key: 'sots',
        label: 'Số dự thi',
        render: (st) => `<td class="val-col">${fmtInt(st.count)}</td><td class="val-col">/${fmtInt(st.totalRoster)} ĐK</td>`,
      },
      {
        key: 'absent',
        label: 'Vắng thi (x)',
        render: (st) =>
          `<td class="val-col text-thpt-purple">${fmtInt(st.absentCount)}</td><td class="val-col text-thpt-purple">${fmtPct(st.absentPct, 2)}</td>`,
      },
      {
        key: 'dtb',
        label: 'Điểm TB',
        render: (st) => `<td class="val-col text-thpt-red">${fmtFixed(st.mean, 2)}</td><td class="val-col"></td>`,
      },
      {
        key: 'median',
        label: 'Trung vị',
        render: (st) => `<td class="val-col">${fmtDec(st.median, 2)}</td><td class="val-col"></td>`,
      },
      {
        key: 'dlc',
        label: 'Độ lệch chuẩn',
        render: (st) => `<td class="val-col text-thpt-red">${fmtFixed(st.stdDev, 2)}</td><td class="val-col"></td>`,
      },
      {
        key: 'mad',
        label: 'MAD',
        render: (st) => `<td class="val-col">${fmtDec(st.mad, 2)}</td><td class="val-col"></td>`,
      },
      {
        key: 'lt5',
        label: 'Dưới 5 (< 5.0)',
        render: (st) =>
          `<td class="val-col text-thpt-purple">${fmtInt(st.lt5Count)}</td><td class="val-col text-thpt-purple">${fmtPct(st.lt5Pct, 2)}</td>`,
      },
      {
        key: 'gte7',
        label: 'Khá giỏi (>= 7.0)',
        render: (st) =>
          `<td class="val-col text-thpt-purple">${fmtInt(st.gte7Count)}</td><td class="val-col text-thpt-purple">${fmtPct(st.gte7Pct, 2)}</td>`,
      },
      {
        key: 'mode',
        label: 'Mode',
        render: (st) => `<td class="val-col">${fmtDec(st.mode, 2)}</td><td class="val-col"></td>`,
      },
      {
        key: 'score10',
        label: 'Điểm 10',
        render: (st) => `<td class="val-col text-thpt-red">${fmtInt(st.score10Count)}</td><td class="val-col"></td>`,
      },
      {
        key: 'score0',
        label: 'Điểm 0',
        render: (st) => `<td class="val-col">${fmtInt(st.score0Count)}</td><td class="val-col"></td>`,
      },
      {
        key: 'lte1',
        label: 'Điểm <= 1.0',
        render: (st) => `<td class="val-col">${fmtInt(st.lte1Count)}</td><td class="val-col">${fmtPct(st.lte1Pct, 2)}</td>`,
      },
    ];

    let tbodyHtml = '<tbody>';
    rowsConfig.forEach((rc) => {
      tbodyHtml += `<tr><td class="metric-col">${escapeHtml(rc.label)}</td>`;
      sessionStatsList.forEach((item) => {
        tbodyHtml += rc.render(item.stats);
      });
      tbodyHtml += `</tr>`;
    });
    tbodyHtml += '</tbody>';
    table.innerHTML = theadHtml + tbodyHtml;

    drawMultiSessionOverlayChart(document.getElementById('multiSessionCanvas'), sessionStatsList);
  }

  function drawMultiSessionOverlayChart(canvas, sessionStatsList, customDims = null) {
    if (!canvas || !sessionStatsList || sessionStatsList.length === 0) return;
    const dpr = customDims ? customDims.scale : 1;
    const width = customDims ? customDims.width : canvas.parentElement.clientWidth || 900;
    const height = customDims ? customDims.height : canvas.parentElement.clientHeight || 290;

    if (customDims) {
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
    }

    const ctx = customDims ? canvas.getContext('2d') : createSvgChartContext(canvas, width, height);
    ctx.save();
    ctx.scale(dpr, dpr);

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);

    const padTop = 42;
    const padBottom = 52;
    const padLeft = 48;
    const padRight = 18;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    const palette = ['#27397c', '#ee642c', '#5265ab', '#f38b5f', '#1d2b61', '#c94b16'];

    let maxPct = 10;
    sessionStatsList.forEach((s) => {
      s.stats.bins.forEach((b) => {
        if (b.pct > maxPct) maxPct = b.pct;
      });
    });
    const niceMaxPct = Math.ceil((maxPct * 1.2) / 5) * 5;

    const yTicks = 5;
    ctx.font = '600 10.5px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= yTicks; i++) {
      const val = (niceMaxPct / yTicks) * i;
      const y = padTop + plotH - (val / niceMaxPct) * plotH;
      ctx.strokeStyle = i === 0 ? '#cbd5e1' : '#f1f5f9';
      if (i > 0) ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(padLeft + plotW, y);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = '#64748b';
      ctx.fillText(fmtFixed(val, 0) + '%', padLeft - 8, y);
    }

    let legendX = padLeft;
    sessionStatsList.forEach((item, idx) => {
      const color = palette[idx % palette.length];
      ctx.fillStyle = color;
      drawRoundedBadge(ctx, legendX, 12, 12, 12, 3);
      ctx.fillStyle = '#0f172a';
      ctx.font = '700 11.5px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      const label = `${item.session.shortName} (ĐTB: ${fmtFixed(item.stats.mean, 2)})`;
      ctx.fillText(label, legendX + 17, 18);
      legendX += ctx.measureText(label).width + 34;
    });

    const binsRef = sessionStatsList[0].stats.bins;
    const numBins = binsRef.length;
    const slotW = plotW / numBins;
    const groupW = slotW * 0.76;
    const singleBarW = Math.max(4, groupW / sessionStatsList.length);

    for (let bIdx = 0; bIdx < numBins; bIdx++) {
      const groupStartX = padLeft + bIdx * slotW + (slotW - groupW) / 2;
      sessionStatsList.forEach((item, sIdx) => {
        const bin = item.stats.bins[bIdx];
        const barH = (bin.pct / niceMaxPct) * plotH;
        const x = groupStartX + sIdx * singleBarW;
        const y = padTop + plotH - barH;
        ctx.fillStyle = palette[sIdx % palette.length];
        drawRoundedTopRect(ctx, x, y, singleBarW - 1.5, barH, 3);
      });

      const centerX = padLeft + bIdx * slotW + slotW / 2;
      ctx.save();
      ctx.translate(centerX, padTop + plotH + 9);
      ctx.rotate(-Math.PI / 4.2);
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#475569';
      ctx.font = '600 10px Inter, sans-serif';
      ctx.fillText(binsRef[bIdx].shortLabel, 0, 0);
      ctx.restore();
    }

    ctx.restore();
    if (ctx.commitSvg) ctx.commitSvg();
  }

  // ============================================================================
  // SECTION 3: THỐNG KÊ THEO KHỐI LỚP & GIÁO VIÊN
  // ============================================================================
  function renderGroupRankingSection() {
    const sess = getCurrentSession();
    if (!sess) return;
    const subjRecords = getFilteredRecords(sess, state.currentSubject, 'ALL', 'ALL');

    const subView1 = document.getElementById('subViewTeacherByGrade');
    const subView2 = document.getElementById('subViewGradeSummary');
    const compareSelect = document.getElementById('compareGradeFilter');

    if (state.groupStatMode === 'teacher_by_grade') {
      subView1.style.display = '';
      subView2.style.display = 'none';
      if (compareSelect) compareSelect.style.display = '';
      renderTeacherByGradeSubView(subjRecords);
    } else {
      subView1.style.display = 'none';
      subView2.style.display = '';
      if (compareSelect) compareSelect.style.display = 'none';
      renderGradeSummarySubView(subjRecords);
    }
  }

  function renderTeacherByGradeSubView(subjRecords) {
    const wrap = document.getElementById('teacherByGradeTablesWrap');
    if (!wrap) return;

    const allGrades = Array.from(
      new Set(subjRecords.map((r) => String(r.grade)).filter((g) => g && g !== 'Chưa rõ'))
    ).sort((a, b) => Number(a) - Number(b));

    const gradesToShow =
      state.compareGradeFilter === 'ALL'
        ? allGrades
        : allGrades.filter((g) => String(g) === String(state.compareGradeFilter));

    const chartItems = [];
    let html = '';

    gradesToShow.forEach((grade) => {
      const gradeRecs = subjRecords.filter((r) => String(r.grade) === String(grade));
      const gradeTotalStats = computeStatistics(gradeRecs, 0.5);
      const groupMean = gradeTotalStats.mean;

      const teachersInGrade = Array.from(new Set(gradeRecs.map((r) => r.teacher).filter(Boolean)));

      const teacherRows = teachersInGrade
        .map((teacher) => {
          const recs = gradeRecs.filter((r) => r.teacher === teacher);
          const st = computeStatistics(recs, 0.5);
          const diff = st.mean - groupMean;
          return {
            grade,
            teacher,
            stats: st,
            groupMean,
            diff,
          };
        })
        .sort((a, b) => b.stats.mean - a.stats.mean || b.stats.maxScore - a.stats.maxScore);

      teacherRows.forEach((tr) => {
        chartItems.push({
          label: `K${tr.grade} - ${tr.teacher}`,
          grade: tr.grade,
          teacher: tr.teacher,
          mean: tr.stats.mean,
          groupMean: tr.groupMean,
          diff: tr.diff,
        });
      });

      html += `
        <div class="thpt-rank-box animate-fade-in">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
            <h3 style="margin-bottom: 0;">
              <i class="fa-solid fa-layer-group" style="color:#27397c; margin-right:5px;"></i>KHỐI <span class="highlight-red">${escapeHtml(String(grade))}</span>
            </h3>
            <div style="display:flex; flex-wrap:wrap; gap:6px;">
              <span class="mini-stat-chip"><i class="fa-solid fa-user-check"></i> Dự thi: <b>${fmtInt(gradeTotalStats.count)}</b></span>
              <span class="mini-stat-chip" style="color:#ee642c; border-color:#fbd5c4; background:#fef2ec;"><i class="fa-solid fa-user-slash"></i> Vắng: <b>${fmtInt(gradeTotalStats.absentCount)}</b></span>
              <span class="mini-stat-chip" style="color:#ee642c; border-color:#fbd5c4; background:#fef2ec;"><i class="fa-solid fa-chart-line"></i> ĐTB Nhóm: <b>${fmtFixed(groupMean, 2)}</b></span>
              <span class="mini-stat-chip" style="color:#27397c; border-color:#d5dcf0; background:#eef1f8;"><i class="fa-solid fa-trophy"></i> Cao nhất: <b>${fmtFixed(gradeTotalStats.maxScore, 2)}</b></span>
            </div>
          </div>
          <div style="overflow-x: auto; border-radius: 10px; border: 1px solid #cbd5e1;">
            <table class="thpt-rank-table">
              <thead>
                <tr>
                  <th style="width: 46px;">#</th>
                  <th style="text-align: left;">Giáo viên</th>
                  <th>Dự thi</th>
                  <th>Vắng (x)</th>
                  <th>ĐTB GV</th>
                  <th>ĐTB Nhóm</th>
                  <th>Chênh lệch</th>
                  <th>Cao nhất</th>
                  <th>&gt;= 8.0</th>
                  <th>Điểm 10</th>
                  <th>&lt; 5.0</th>
                </tr>
              </thead>
              <tbody>
                ${teacherRows
                  .map((tr, idx) => {
                    const diffSign = tr.diff >= 0 ? '+' : '';
                    const diffClass = tr.diff >= 0 ? 'diff-pos' : 'diff-neg';
                    return `
                  <tr>
                    <td class="stt-col">${idx + 1}</td>
                    <td style="font-weight: 700;"><i class="fa-regular fa-user" style="color:#27397c; margin-right:5px; font-size:11.5px;"></i>GV ${escapeHtml(tr.teacher)}</td>
                    <td class="num-col">${fmtInt(tr.stats.count)}</td>
                    <td class="num-col text-thpt-purple">${fmtInt(tr.stats.absentCount)}</td>
                    <td class="num-col text-thpt-red" style="font-size: 14px;">${fmtFixed(tr.stats.mean, 2)}</td>
                    <td class="num-col" style="font-weight: 700; color: #27397c;">${fmtFixed(tr.groupMean, 2)}</td>
                    <td class="num-col ${diffClass}">${diffSign}${fmtFixed(tr.diff, 2)}</td>
                    <td class="num-col" style="font-weight: 800; color: #27397c;">${fmtFixed(tr.stats.maxScore, 2)}</td>
                    <td class="num-col" style="font-weight: 700; color: #27397c;">${fmtInt(tr.stats.gte8Count)} (${fmtFixed(tr.stats.gte8Pct, 1)}%)</td>
                    <td class="num-col text-thpt-red">${fmtInt(tr.stats.score10Count)}</td>
                    <td class="num-col" style="font-weight: 700; color: #ee642c;">${fmtInt(tr.stats.lt5Count)} (${fmtFixed(tr.stats.lt5Pct, 1)}%)</td>
                  </tr>
                `;
                  })
                  .join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    });

    wrap.innerHTML = html;
    drawTeacherGradeCompareChart(document.getElementById('teacherGradeCompareCanvas'), chartItems);
  }

  function drawTeacherGradeCompareChart(canvas, items, customDims = null) {
    if (!canvas || !items || items.length === 0) return;
    const dpr = customDims ? customDims.scale : 1;
    const width = customDims ? customDims.width : canvas.parentElement.clientWidth || 860;
    const height = customDims ? customDims.height : canvas.parentElement.clientHeight || 295;

    if (customDims) {
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
    }

    const ctx = customDims ? canvas.getContext('2d') : createSvgChartContext(canvas, width, height);
    ctx.save();
    ctx.scale(dpr, dpr);

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);

    const padTop = 46;
    const padBottom = 60;
    const padLeft = 48;
    const padRight = 18;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    // Modern Legend (Strictly 2-color palette: #27397c & #ee642c)
    ctx.fillStyle = '#27397c';
    drawRoundedBadge(ctx, padLeft, 12, 13, 13, 4);
    ctx.fillStyle = '#0f172a';
    ctx.font = '700 12px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText('ĐTB Khối của Giáo viên', padLeft + 18, 18.5);

    ctx.fillStyle = '#ee642c';
    drawRoundedBadge(ctx, padLeft + 195, 12, 13, 13, 4);
    ctx.fillStyle = '#0f172a';
    ctx.fillText('ĐTB Chung cả Nhóm (cùng Khối)', padLeft + 213, 18.5);

    for (let i = 0; i <= 5; i++) {
      const val = i * 2;
      const y = padTop + plotH - (val / 10) * plotH;
      ctx.strokeStyle = i === 0 ? '#cbd5e1' : '#f1f5f9';
      if (i > 0) ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(padLeft + plotW, y);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = '#64748b';
      ctx.font = '600 11px Inter, sans-serif';
      ctx.textAlign = 'right';
      ctx.fillText(String(val), padLeft - 8, y);
    }

    const n = items.length;
    const slotW = plotW / n;
    const groupW = Math.min(60, slotW * 0.72);
    const barW = groupW / 2;

    items.forEach((it, idx) => {
      const gx = padLeft + idx * slotW + (slotW - groupW) / 2;

      // Bar 1: Teacher's Grade Mean (Solid Navy #27397c)
      const hMean = (it.mean / 10) * plotH;
      const yMean = padTop + plotH - hMean;
      ctx.fillStyle = '#27397c';
      drawRoundedTopRect(ctx, gx, yMean, barW - 2, hMean, 5);

      ctx.fillStyle = '#27397c';
      ctx.font = '700 10.5px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(fmtFixed(it.mean, 2), gx + barW / 2 - 1, yMean - 6);

      // Bar 2: Whole Group's Grade Mean (Solid Orange #ee642c)
      const hGroup = (it.groupMean / 10) * plotH;
      const yGroup = padTop + plotH - hGroup;
      ctx.fillStyle = '#ee642c';
      drawRoundedTopRect(ctx, gx + barW, yGroup, barW - 2, hGroup, 5);

      ctx.fillStyle = '#ee642c';
      ctx.font = '700 10.5px Inter, sans-serif';
      ctx.fillText(fmtFixed(it.groupMean, 2), gx + barW + barW / 2 - 1, yGroup - 6);

      // Delta badge above the pair
      const topY = Math.min(yMean, yGroup) - 21;
      const diffSign = it.diff >= 0 ? '+' : '';
      ctx.fillStyle = it.diff >= 0 ? '#27397c' : '#ee642c';
      ctx.font = '800 10px Inter, sans-serif';
      ctx.fillText(`(${diffSign}${fmtFixed(it.diff, 2)})`, gx + groupW / 2, Math.max(padTop - 8, topY));

      // X label
      const cx = padLeft + idx * slotW + slotW / 2;
      ctx.save();
      ctx.translate(cx, padTop + plotH + 10);
      ctx.rotate(-Math.PI / 5.5);
      ctx.textAlign = 'right';
      ctx.fillStyle = '#334155';
      ctx.font = '600 10.5px Inter, sans-serif';
      ctx.fillText(it.label, 0, 0);
      ctx.restore();
    });

    ctx.restore();
    if (ctx.commitSvg) ctx.commitSvg();
  }

  function renderGradeSummarySubView(subjRecords) {
    const allGrades = Array.from(
      new Set(subjRecords.map((r) => String(r.grade)).filter((g) => g && g !== 'Chưa rõ'))
    ).sort((a, b) => Number(a) - Number(b));

    const gradeStats = allGrades.map((grade) => {
      const recs = subjRecords.filter((r) => String(r.grade) === String(grade));
      const st = computeStatistics(recs, 0.5);
      const scored = recs.filter((r) => !r.absent && r.score !== null).sort((a, b) => b.score - a.score);
      const topScorers =
        scored.length > 0
          ? scored
              .filter((r) => Math.abs(r.score - st.maxScore) < 1e-9)
              .slice(0, 2)
              .map((r) => `${r.name} (GV ${r.teacher})`)
              .join(', ')
          : '-';
      return { grade, st, topScorers };
    });

    const tbodyLeft = document.querySelector('#tableGradeAvgAndMax tbody');
    const tbodyRight = document.querySelector('#tableGradeQuality tbody');

    if (tbodyLeft) {
      tbodyLeft.innerHTML = gradeStats
        .map(
          (g) => `
        <tr>
          <td class="stt-col" style="width: 72px;">Khối ${escapeHtml(String(g.grade))}</td>
          <td class="num-col">${fmtInt(g.st.count)}</td>
          <td class="num-col text-thpt-purple">${fmtInt(g.st.absentCount)}</td>
          <td class="num-col text-thpt-red">${fmtFixed(g.st.mean, 2)}</td>
          <td class="num-col" style="font-weight: 800; color: #27397c;">${fmtFixed(g.st.maxScore, 2)}</td>
          <td style="font-size: 12.5px; font-weight: 600;">${escapeHtml(g.topScorers)}</td>
        </tr>
      `
        )
        .join('');
    }

    if (tbodyRight) {
      tbodyRight.innerHTML = gradeStats
        .map(
          (g) => `
        <tr>
          <td class="stt-col" style="width: 72px;">Khối ${escapeHtml(String(g.grade))}</td>
          <td class="num-col text-thpt-red">${fmtInt(g.st.score10Count)}</td>
          <td class="num-col" style="font-weight:700; color:#27397c;">${fmtInt(g.st.gte8Count)} (${fmtFixed(g.st.gte8Pct, 1)}%)</td>
          <td class="num-col">${fmtInt(g.st.gte7Count)} (${fmtFixed(g.st.gte7Pct, 1)}%)</td>
          <td class="num-col" style="font-weight:700; color:#ee642c;">${fmtInt(g.st.lt5Count)} (${fmtFixed(g.st.lt5Pct, 1)}%)</td>
        </tr>
      `
        )
        .join('');
    }
  }

  // ============================================================================
  // SECTION 4: TOP N HIGHEST SCORING STUDENTS (Scoped to Subject & Grade)
  // ============================================================================
  // ============================================================================
  // SECTION 4: BẢNG ĐIỂM, XẾP HẠNG TOP & VẮNG THI (GỘP CHUNG 1 BẢNG ĐA NĂNG)
  // ============================================================================
  function getUnifiedStudentList(sess, subject, topN, includeTies, teacherFilter = 'ALL', gradeFilter = null) {
    const allRecs = getFilteredRecords(sess, subject, teacherFilter, gradeFilter);
    const scored = allRecs
      .filter((r) => !r.absent && r.score !== null && !isNaN(r.score))
      .slice()
      .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name, 'vi'));
    const absentList = allRecs
      .filter((r) => r.absent || r.score === null || isNaN(r.score))
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name, 'vi'))
      .map((r) => Object.assign({}, r, { rank: null, isAbsent: true }));

    // Count frequency of each score to detect ties
    const scoreFreq = new Map();
    for (let i = 0; i < scored.length; i++) {
      const key = Math.round(scored[i].score * 1000) / 1000;
      scoreFreq.set(key, (scoreFreq.get(key) || 0) + 1);
    }

    // Assign rank based on includeTies ("Đồng hạng"):
    // - When includeTies = true: shared rank tier by score (1, 1, 2, 3, 3...) + mark tied students
    // - When includeTies = false: strict sequential individual rank (1, 2, 3, 4, 5...)
    const rankedScored = [];
    let currentDenseRank = 1;
    for (let i = 0; i < scored.length; i++) {
      if (i > 0 && Math.abs(scored[i].score - scored[i - 1].score) > 1e-9) {
        currentDenseRank++;
      }
      const key = Math.round(scored[i].score * 1000) / 1000;
      const isTiedScore = (scoreFreq.get(key) || 0) > 1;
      const assignedRank = includeTies ? currentDenseRank : i + 1;
      rankedScored.push(
        Object.assign({}, scored[i], {
          rank: assignedRank,
          isTied: Boolean(includeTies && isTiedScore),
          isAbsent: false,
        })
      );
    }

    // Apply Top N limit if topN > 0 (and not specifically filtering ABSENT)
    let workingList = [];
    if (topN > 0 && state.studentStatusFilter !== 'ABSENT') {
      if (includeTies) {
        workingList = rankedScored.filter((r) => r.rank <= topN);
      } else {
        workingList = rankedScored.slice(0, topN);
      }
    } else {
      workingList = rankedScored.concat(absentList);
    }

    // Apply status filter (ALL, SCORED, GT9, LT5, ABSENT) & search query
    const q = state.studentSearchQuery.trim().toLowerCase();
    const finalFiltered = workingList.filter((r) => {
      if (state.studentStatusFilter === 'SCORED' && r.isAbsent) return false;
      if (state.studentStatusFilter === 'ABSENT' && !r.isAbsent) return false;
      if (state.studentStatusFilter === 'LT5' && (r.isAbsent || r.score >= 5)) return false;
      if (state.studentStatusFilter === 'GT9' && (r.isAbsent || r.score < 9)) return false;
      if (q && !r.name.toLowerCase().includes(q) && !r.teacher.toLowerCase().includes(q)) return false;
      return true;
    });

    return {
      list: finalFiltered,
      totalRoster: allRecs.length,
      totalTested: rankedScored.length,
      totalAbsent: absentList.length,
    };
  }

  function renderTopStudentsSection() {
    const sess = getCurrentSession();
    const container = document.getElementById('topStudentsContainer');
    if (!sess || !container) return;

    // 1. Render Interactive Summary Strip (#absentSummaryStrip)
    const baseRecs = getFilteredRecords(sess, state.currentSubject, state.filterTeacher, state.filterGrade);
    const totalAbsent = baseRecs.filter((r) => r.absent || r.score === null).length;
    const totalScored = baseRecs.length - totalAbsent;
    const totalLt5 = baseRecs.filter((r) => !r.absent && r.score !== null && r.score < 5).length;
    const totalGt9 = baseRecs.filter((r) => !r.absent && r.score !== null && r.score >= 9).length;

    const strip = document.getElementById('absentSummaryStrip');
    if (strip) {
      const teachers = Array.from(new Set(baseRecs.map((r) => r.teacher)));
      const curSt = state.studentStatusFilter;
      const chipStyle = (key, baseBg, baseColor, baseBorder) =>
        curSt === key
          ? `cursor:pointer; background:${baseColor}; color:#ffffff; border-color:${baseColor}; box-shadow:0 2px 6px rgba(39,57,124,0.18);`
          : `cursor:pointer; background:${baseBg}; color:${baseColor}; border-color:${baseBorder};`;

      strip.innerHTML =
        `<span class="mini-stat-chip" data-status-chip="ALL" style="${chipStyle('ALL', '#eef1f8', '#27397c', '#b8c4e6')}" title="Bấm để xem tất cả học sinh"><i class="fa-solid fa-users"></i> Tất cả: <b>${baseRecs.length}</b> (${totalScored} dự thi)</span>` +
        `<span class="mini-stat-chip" data-status-chip="GT9" style="${chipStyle('GT9', '#eef1f8', '#27397c', '#b8c4e6')}" title="Bấm để lọc học sinh Trên 9 (>= 9.0)"><i class="fa-solid fa-star"></i> Trên 9 (&gt;= 9.0): <b>${totalGt9}</b></span>` +
        `<span class="mini-stat-chip" data-status-chip="LT5" style="${chipStyle('LT5', '#fef2ec', '#ee642c', '#fbd5c4')}" title="Bấm để lọc học sinh Dưới 5 (< 5.0)"><i class="fa-solid fa-circle-exclamation"></i> Dưới 5 (&lt; 5.0): <b>${totalLt5}</b></span>` +
        `<span class="mini-stat-chip" data-status-chip="ABSENT" style="${chipStyle('ABSENT', '#fef2ec', '#ee642c', '#fbd5c4')}" title="Bấm để lọc học sinh Vắng thi (x)"><i class="fa-solid fa-user-slash"></i> Vắng (x): <b>${totalAbsent}/${baseRecs.length}</b></span>` +
        teachers
          .map((t) => {
            const cnt = baseRecs.filter((r) => r.teacher === t && (r.absent || r.score === null)).length;
            return `<span class="mini-stat-chip" style="background:#ffffff; border-color:#cbd5e1; color:#27397c;"><i class="fa-regular fa-user"></i> ${escapeHtml(t)}: <b style="color:#ee642c;">${cnt}</b> vắng</span>`;
          })
          .join('');

      strip.querySelectorAll('[data-status-chip]').forEach((chip) => {
        chip.addEventListener('click', () => {
          const val = chip.getAttribute('data-status-chip') || 'ALL';
          state.studentStatusFilter = val;
          const statusSel = document.getElementById('studentStatusFilter');
          if (statusSel) statusSel.value = val;
          if (val === 'ABSENT' && state.topN > 0) {
            state.topN = 0;
            const topNInput = document.getElementById('topNInput');
            if (topNInput) topNInput.value = '';
            document.querySelectorAll('.quick-top-btn').forEach((b) => {
              b.classList.toggle('active', parseInt(b.getAttribute('data-top'), 10) === 0);
            });
          }
          renderTopStudentsSection();
        });
      });
    }

    // 2. Render Unified Table(s)
    const topN = Math.max(0, parseInt(state.topN, 10) || 0);
    const pairs = [];
    const allowedSubjs = getAllowedSubjects(sess);

    const allSubjChk = document.getElementById('showAllSubjectsTopCheckbox');
    const allSubjLabel = allSubjChk?.closest('label');
    if (allSubjLabel) {
      allSubjLabel.style.display = allowedSubjs.length > 1 ? '' : 'none';
    }

    if (state.showAllSubjectsTop && allowedSubjs.length > 1) {
      allowedSubjs.forEach((subj) => {
        const grades = getGradesForSubject(sess, subj);
        grades.forEach((g) => pairs.push({ subj, grade: g, teacher: 'ALL' }));
      });
    } else {
      pairs.push({ subj: state.currentSubject, grade: state.filterGrade, teacher: state.filterTeacher });
    }

    const statusBadgeLabelMap = {
      ALL: topN > 0 ? `TOP ${topN} ĐIỂM CAO` : 'BẢNG ĐIỂM & XẾP HẠNG',
      SCORED: topN > 0 ? `TOP ${topN} CÓ ĐIỂM` : 'DANH SÁCH DỰ THI',
      GT9: 'HỌC SINH TRÊN 9 (>= 9.0)',
      LT5: 'HỌC SINH DƯỚI 5 (< 5.0)',
      ABSENT: 'DANH SÁCH VẮNG THI (X)',
    };
    const modePrefix = statusBadgeLabelMap[state.studentStatusFilter] || 'BẢNG ĐIỂM & XẾP HẠNG';

    let html = '';
    pairs.forEach(({ subj, grade, teacher }) => {
      const { list, totalRoster, totalTested } = getUnifiedStudentList(
        sess,
        subj,
        topN,
        state.includeTies,
        teacher,
        grade
      );
      const tLabel = teacher !== 'ALL' ? ` • GV ${teacher}` : '';

      html += `
        <div class="thpt-rank-box animate-fade-in">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; flex-wrap:wrap; gap:8px;">
            <h3 style="margin-bottom:0;">
              <i class="fa-solid fa-crown" style="color:#ee642c; margin-right:5px;"></i><span class="highlight-red">${escapeHtml(modePrefix)}</span> — <span style="color:#27397c;">${escapeHtml(subj.toUpperCase())} (KHỐI ${escapeHtml(String(grade))})</span>${escapeHtml(tLabel)}
            </h3>
            <span class="mini-stat-chip">
              <i class="fa-solid fa-users"></i> Hiển thị: <b>${list.length}</b> / ${totalTested} dự thi (${totalRoster} ĐK)
            </span>
          </div>
          <div style="overflow-x:auto; border-radius:10px; border:1px solid #cbd5e1;">
            <table class="thpt-rank-table">
              <thead>
                <tr>
                  <th style="width:78px;">Hạng</th>
                  <th style="text-align:left;">Học sinh</th>
                  <th style="width:85px;">Khối</th>
                  <th style="width:135px;">Bộ môn</th>
                  <th style="width:155px;">Giáo viên</th>
                  <th style="width:110px;">Ngày thi</th>
                  <th style="width:120px;">Điểm / TT</th>
                </tr>
              </thead>
              <tbody>
                ${
                  list.length === 0
                    ? `<tr><td colspan="7" style="text-align:center; padding:18px; color:#64748b; font-weight:600;">Không có học sinh nào khớp bộ lọc hiện tại</td></tr>`
                    : list
                        .map((item, idx) => {
                          const isAbs = item.isAbsent || item.absent || item.score === null;
                          let rankBadge = '-';
                          if (!isAbs && item.rank !== null) {
                            if (item.rank === 1) rankBadge = `<span class="rank-medal rank-1">1</span>`;
                            else if (item.rank === 2) rankBadge = `<span class="rank-medal rank-2">2</span>`;
                            else if (item.rank === 3) rankBadge = `<span class="rank-medal rank-3">3</span>`;
                            else rankBadge = `<b>${item.rank}</b>`;
                          } else {
                            rankBadge = `<span style="color:#ee642c; font-weight:800;">KĐ</span>`;
                          }

                          const hl = getStudentHighlightMeta(item.score, isAbs);
                          const badgeHtml = isAbs
                            ? `<span class="score-pill-badge score-absent">x (Vắng)</span>`
                            : `<span class="score-pill-badge ${hl.scoreClass}">${fmtFixed(item.score, 2)}</span>`;

                          return `
                            <tr class="${hl.rowClass}">
                              <td class="stt-col">${rankBadge}</td>
                              <td class="${hl.nameClass}" style="font-weight:700;">${escapeHtml(item.name)}${hl.nameTagHtml}</td>
                              <td class="num-col">Khối ${escapeHtml(String(item.grade))}</td>
                              <td class="num-col">${escapeHtml(item.subject)}</td>
                              <td class="num-col">GV ${escapeHtml(item.teacher)}</td>
                              <td class="num-col">${escapeHtml(item.examDate || sess.date || '-')}</td>
                              <td class="num-col">${badgeHtml}</td>
                            </tr>
                          `;
                        })
                        .join('')
                }
              </tbody>
            </table>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  }

  function renderAbsentAndSearchSection() {
    // Unified into renderTopStudentsSection()
  }

  // ============================================================================
  // SECTION 6: TOÀN CẢNH CÁC MÔN (Mỗi môn có tùy chọn chọn Khối riêng)
  // ============================================================================
  function renderAllSubjectsOverview() {
    const sess = getCurrentSession();
    const container = document.getElementById('allSubjectsGridContainer');
    if (!sess || !container) return;
    container.innerHTML = '';

    const allowedSubjs = getAllowedSubjects(sess);
    allowedSubjs.forEach((subj, idx) => {
      const grades = getGradesForSubject(sess, subj);
      if (!state.overviewSelectedGrades[subj] || !grades.includes(String(state.overviewSelectedGrades[subj]))) {
        state.overviewSelectedGrades[subj] = grades[0] || '10';
      }
      const selectedGrade = state.overviewSelectedGrades[subj];

      const recs = getFilteredRecords(sess, subj, 'ALL', selectedGrade);
      const st = computeStatistics(recs, 0.5);

      const card = document.createElement('div');
      card.className = 'mini-subject-card animate-fade-in';
      const canvasId = `miniCanvas_${idx}`;
      const iconCls = getSubjectIconClass(subj);

      const gradeBtnsHtml = grades
        .map((g) => {
          const isAct = String(g) === String(selectedGrade) ? 'active' : '';
          return `<button type="button" class="mini-grade-btn ${isAct}" data-ov-grade="${escapeHtml(String(g))}">K${escapeHtml(String(g))}</button>`;
        })
        .join('');

      card.innerHTML = `
        <div style="background:#f8fafc; padding:10px 14px; border-bottom:1px solid #e2e8f0; display:flex; flex-direction:column; gap:7px;">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
            <div style="font-size:14px; font-weight:800; color:#27397c; display:flex; align-items:center; gap:6px;">
              <i class="${iconCls}" style="color:#ee642c;"></i>
              <span>${escapeHtml(subj.toUpperCase())} • KHỐI ${escapeHtml(String(selectedGrade))}</span>
            </div>
            <div class="mini-grade-pills">
              ${gradeBtnsHtml}
            </div>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div style="font-size:11.5px; color:#475569; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
              <span><i class="fa-solid fa-user-check" style="color:#27397c;"></i> <b style="color:#27397c;">${fmtInt(st.count)}</b></span>
              <span><i class="fa-solid fa-user-slash" style="color:#ee642c;"></i> <b style="color:#ee642c;">${st.absentCount}</b></span>
              <span>ĐTB: <b style="color:#ee642c;">${fmtFixed(st.mean, 2)}</b></span>
              <span>Điểm 10: <b style="color:#27397c;">${st.score10Count}</b></span>
            </div>
            <div style="display:flex; gap:5px;">
              <button type="button" class="btn btn-outline btn-sm" data-focus-subj="${escapeHtml(subj)}"><i class="fa-solid fa-expand"></i> Chi tiết</button>
              <button type="button" class="btn btn-primary btn-sm" data-export-subj="${escapeHtml(subj)}"><i class="fa-solid fa-download"></i> 6K</button>
            </div>
          </div>
        </div>
        <div style="padding:12px; height:240px; background:#fff;">
          <canvas id="${canvasId}" style="width:100%; height:100%; display:block;"></canvas>
        </div>
      `;

      container.appendChild(card);

      requestAnimationFrame(() => {
        const miniCanvas = document.getElementById(canvasId);
        if (miniCanvas) {
          drawMiniSubjectChart(miniCanvas, st);
          miniCanvas.addEventListener('mousemove', (e) => {
            const rect = miniCanvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;
            const hit = (miniCanvas._barRects || []).find(
              (b) => mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h
            );
            miniCanvas.style.cursor = hit ? 'pointer' : 'default';
          });
          miniCanvas.addEventListener('click', (e) => {
            const rect = miniCanvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;
            const hit = (miniCanvas._barRects || []).find(
              (b) => mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h
            );
            if (hit) {
              openBinStudentsModal(st, hit.index, subj, selectedGrade, 'ALL', sess);
            }
          });
        }
      });

      card.querySelectorAll('[data-ov-grade]').forEach((gBtn) => {
        gBtn.addEventListener('click', () => {
          state.overviewSelectedGrades[subj] = gBtn.getAttribute('data-ov-grade');
          renderAllSubjectsOverview();
        });
      });

      card.querySelector('[data-focus-subj]').addEventListener('click', () => {
        state.currentSubject = subj;
        state.filterGrade = selectedGrade;
        state.filterTeacher = 'ALL';
        state.viewMode = 'phodiem';
        updateViewModeVisibility();
        refreshAllUI(true);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });

      card.querySelector('[data-export-subj]').addEventListener('click', () => {
        exportHighResPhoDiemCard(sess, subj, 'ALL', selectedGrade);
      });
    });
  }

  function drawMiniSubjectChart(canvas, stats) {
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.parentElement.clientWidth || 500;
    const height = canvas.parentElement.clientHeight || 216;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);

    const ctx = canvas.getContext('2d');
    ctx.save();
    ctx.scale(dpr, dpr);

    const padTop = 24;
    const padBottom = 42;
    const padLeft = 36;
    const padRight = 12;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    const niceMax = computeNiceYMax(stats.maxBinCount * 1.2);
    const numBins = stats.bins.length;
    const slotW = plotW / numBins;
    const barW = Math.max(5, slotW * 0.68);
    canvas._barRects = [];

    for (let i = 0; i <= 4; i++) {
      const y = padTop + (plotH / 4) * i;
      ctx.strokeStyle = i === 4 ? '#cbd5e1' : '#f1f5f9';
      if (i < 4) ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(padLeft + plotW, y);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    stats.bins.forEach((bin, i) => {
      const barH = (bin.count / niceMax) * plotH;
      const x = padLeft + i * slotW + (slotW - barW) / 2;
      const y = padTop + plotH - barH;
      const cx = padLeft + i * slotW + slotW / 2;

      if (bin.high <= 5.001) {
        ctx.fillStyle = '#ee642c';
      } else {
        ctx.fillStyle = '#27397c';
      }

      if (barH > 0.5) {
        drawRoundedTopRect(ctx, x, y, barW, barH, 4);
      } else {
        ctx.fillStyle = '#e2e8f0';
        ctx.fillRect(x, padTop + plotH - 1.5, barW, 1.5);
      }

      canvas._barRects.push({
        index: i,
        x: padLeft + i * slotW,
        y: padTop,
        w: slotW,
        h: plotH,
      });

      if (bin.count > 0) {
        ctx.fillStyle = '#27397c';
        ctx.font = '700 9px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(String(bin.count), cx, y - 3);
      }

      ctx.save();
      ctx.translate(cx, padTop + plotH + 7);
      ctx.rotate(-Math.PI / 4.2);
      ctx.font = '600 8.5px Inter, sans-serif';
      ctx.fillStyle = '#64748b';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(bin.shortLabel, 0, 0);
      ctx.restore();
    });

    ctx.restore();
  }

  // ============================================================================
  // ULTRA-HD 6K EXPORTERS (Default 6K PNG)
  // ============================================================================
  function getExportSettings() {
    const scale = parseInt(document.getElementById('exportQualitySelect')?.value || '6', 10);
    const format = document.getElementById('exportFormatSelect')?.value || 'png';
    return { scale, format };
  }

  function slugify(str) {
    return String(str || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/đ/g, 'd')
      .replace(/Đ/g, 'D')
      .replace(/[^a-zA-Z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '');
  }

  function drawExportWatermarkFooter(ctx, baseW, baseH, session) {
    const now = new Date();
    const dd = String(now.getDate()).padStart(2, '0');
    const mm = String(now.getMonth() + 1).padStart(2, '0');
    const yyyy = now.getFullYear();
    const downloadDateStr = `${dd}/${mm}/${yyyy}`;

    const sessObj = session || getCurrentSession();
    const examLabel = cleanSessionLabel(sessObj?.shortName || sessObj?.name || 'Lần 1');
    const origFile = sessObj?.fileName || `${sessObj?.fileCode || 'L1'}.xlsx`;

    const footerY = baseH - 18;

    // Bottom-left: Thực hiện bởi Minh Tuấn
    ctx.save();
    ctx.fillStyle = 'rgba(39, 57, 124, 0.58)';
    ctx.font = '600 13.5px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText('Thực hiện bởi Minh Tuấn', 40, footerY);

    // Bottom-right: Lần thi + Tên file dữ liệu gốc + Ngày tải xuống
    ctx.fillStyle = 'rgba(71, 85, 105, 0.65)';
    ctx.font = '500 13px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(
      `Đợt thi: ${examLabel}  •  File dữ liệu gốc: ${origFile}  •  Tải xuống ngày: ${downloadDateStr}`,
      baseW - 40,
      footerY
    );
    ctx.restore();
  }

  function exportHighResPhoDiemCard(session, subject, teacherFilter = 'ALL', gradeFilter = null) {
    const { scale, format } = getExportSettings();
    const targetGrade = gradeFilter || state.filterGrade;
    const records = getFilteredRecords(session, subject, teacherFilter, targetGrade);
    const stats = computeStatistics(records, state.binStep);

    const teacherSuffix = teacherFilter !== 'ALL' ? ` • GV ${teacherFilter}` : '';
    const filenameBase = `Pho_Diem_${slugify(subject)}_Khoi_${slugify(targetGrade)}_${slugify(session.shortName)}`;

    const baseW = 1400;
    const baseH = 716;
    const offCanvas = document.createElement('canvas');
    offCanvas.width = baseW * scale;
    offCanvas.height = baseH * scale;
    const ctx = offCanvas.getContext('2d');
    ctx.save();
    ctx.scale(scale, scale);

    ctx.fillStyle = '#f8fafc';
    ctx.fillRect(0, 0, baseW, baseH);

    ctx.fillStyle = '#27397c';
    ctx.font = '800 24px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(
      `PHỔ ĐIỂM MÔN ${subject.toUpperCase()} — KHỐI ${String(targetGrade).toUpperCase()}${teacherSuffix.toUpperCase()}`,
      40,
      30
    );

    ctx.fillStyle = '#ee642c';
    ctx.font = '800 16px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(state.centerName.toUpperCase(), baseW - 40, 34);

    const chartX = 40;
    const chartY = 76;
    const chartW = 880;
    const chartH = 584;

    const subCanvas = document.createElement('canvas');
    drawTHPTChartOnCanvas(subCanvas, stats, 1, -1, {
      width: chartW,
      height: chartH,
      scale,
      subjectOverride: subject,
      gradeOverride: targetGrade,
      teacherOverride: teacherFilter,
    });
    ctx.drawImage(subCanvas, 0, 0, chartW * scale, chartH * scale, chartX, chartY, chartW, chartH);
    ctx.strokeStyle = '#cbd5e1';
    ctx.strokeRect(chartX, chartY, chartW, chartH);

    const tableX = 940;
    const tableY = 76;
    const tableW = 420;
    const tableH = 584;

    const tableRows = [
      { name: 'Số TS dự thi', val: fmtInt(stats.count), pct: `/${fmtInt(stats.totalRoster)} ĐK`, color: '#0f172a' },
      { name: 'Vắng thi (x)', val: fmtInt(stats.absentCount), pct: fmtPct(stats.absentPct, 2), color: '#27397c' },
      { name: 'ĐTB', val: fmtFixed(stats.mean, 2), pct: '', color: '#ee642c' },
      { name: 'Trung vị', val: fmtDec(stats.median, 2), pct: '', color: '#0f172a' },
      { name: 'ĐLC', val: fmtFixed(stats.stdDev, 2), pct: '', color: '#ee642c' },
      { name: 'MAD', val: fmtDec(stats.mad, 2), pct: '', color: '#0f172a' },
      { name: '<5', val: fmtInt(stats.lt5Count), pct: fmtPct(stats.lt5Pct, 2), color: '#ee642c' },
      { name: '> = 7', val: fmtInt(stats.gte7Count), pct: fmtPct(stats.gte7Pct, 2), color: '#27397c' },
      { name: 'Mode', val: fmtFixed(stats.mode, 2), pct: '', color: '#0f172a' },
      { name: 'Điểm 10', val: fmtInt(stats.score10Count), pct: '', color: '#ee642c' },
      { name: 'Điểm 0', val: fmtInt(stats.score0Count), pct: '', color: '#0f172a' },
      { name: '< = 1', val: fmtInt(stats.lte1Count), pct: fmtPct(stats.lte1Pct, 2), color: '#0f172a' },
    ];

    const rowH = tableH / tableRows.length;
    const col1W = 140;
    const col2W = 140;
    const col3W = tableW - col1W - col2W;

    tableRows.forEach((r, idx) => {
      const ry = tableY + idx * rowH;
      ctx.fillStyle = '#27397c';
      ctx.fillRect(tableX, ry, col1W, rowH);

      ctx.fillStyle = idx % 2 === 0 ? '#f8fafc' : '#ffffff';
      ctx.fillRect(tableX + col1W, ry, col2W + col3W, rowH);

      ctx.strokeStyle = '#cbd5e1';
      ctx.strokeRect(tableX, ry, col1W, rowH);
      ctx.strokeRect(tableX + col1W, ry, col2W, rowH);
      ctx.strokeRect(tableX + col1W + col2W, ry, col3W, rowH);

      ctx.fillStyle = '#ffffff';
      ctx.font = '700 16.5px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(r.name, tableX + 14, ry + rowH / 2);

      ctx.fillStyle = r.color;
      ctx.font = r.color !== '#0f172a' ? '800 18px Inter, sans-serif' : '700 17px Inter, sans-serif';
      ctx.textAlign = 'right';
      ctx.fillText(r.val, tableX + col1W + col2W - 12, ry + rowH / 2);

      if (r.pct) {
        ctx.fillStyle = r.color === '#27397c' ? '#27397c' : r.color === '#ee642c' ? '#ee642c' : '#475569';
        ctx.font = '600 15.5px Inter, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(r.pct, tableX + tableW - 12, ry + rowH / 2);
      }
    });

    drawExportWatermarkFooter(ctx, baseW, baseH, session);
    ctx.restore();
    triggerCanvasDownload(offCanvas, filenameBase, format === 'svg' ? 'png' : format);
    showToast(`Đã tải ảnh phổ điểm ${subject} - Khối ${targetGrade} (${scale}K)`);
  }

  function exportMultiSessionImage() {
    const { scale, format } = getExportSettings();
    const subj = state.currentSubject;
    const grade = state.filterGrade;
    const sessionStatsList = state.sessions.map((sess) => ({
      session: sess,
      stats: computeStatistics(getFilteredRecords(sess, subj, state.filterTeacher, grade), 0.5),
    }));

    const baseW = Math.max(1360, 420 + sessionStatsList.length * 280);
    const baseH = 980;
    const canvas = document.createElement('canvas');
    canvas.width = baseW * scale;
    canvas.height = baseH * scale;
    const ctx = canvas.getContext('2d');
    ctx.save();
    ctx.scale(scale, scale);

    ctx.fillStyle = '#f8fafc';
    ctx.fillRect(0, 0, baseW, baseH);

    ctx.fillStyle = '#27397c';
    ctx.font = '800 22px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(
      `THỐNG KÊ MÔN ${subj.toUpperCase()} (KHỐI ${grade}) QUA CÁC LẦN THI — ${state.centerName.toUpperCase()}`,
      40,
      26
    );

    const tx = 40;
    const ty = 68;
    const tw = baseW - 80;
    const labelColW = 340;
    const sessColW = (tw - labelColW) / sessionStatsList.length;
    const rowH = 36;

    ctx.fillStyle = '#27397c';
    ctx.fillRect(tx, ty, tw, 42);
    ctx.strokeStyle = '#1d2b61';
    ctx.strokeRect(tx, ty, labelColW, 42);
    ctx.fillStyle = '#ffffff';
    ctx.font = '700 15px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(`CHỈ SỐ (KHỐI ${grade}) / LẦN THI`, tx + labelColW / 2, ty + 21);

    sessionStatsList.forEach((item, idx) => {
      const sx = tx + labelColW + idx * sessColW;
      ctx.strokeRect(sx, ty, sessColW, 42);
      ctx.fillText(item.session.shortName, sx + sessColW / 2, ty + 21);
    });

    const metricRows = [
      { label: 'Số thí sinh dự thi', v1: (s) => fmtInt(s.count), v2: (s) => `/${fmtInt(s.totalRoster)} ĐK`, color: '#0f172a' },
      { label: 'Số thí sinh vắng thi (x)', v1: (s) => fmtInt(s.absentCount), v2: (s) => fmtPct(s.absentPct, 2), color: '#27397c' },
      { label: 'Điểm trung bình', v1: (s) => fmtFixed(s.mean, 2), v2: () => '', color: '#ee642c' },
      { label: 'Trung vị', v1: (s) => fmtDec(s.median, 2), v2: () => '', color: '#0f172a' },
      { label: 'Độ lệch chuẩn', v1: (s) => fmtFixed(s.stdDev, 2), v2: () => '', color: '#ee642c' },
      { label: 'Độ lệch tuyệt đối trung vị (MAD)', v1: (s) => fmtDec(s.mad, 2), v2: () => '', color: '#0f172a' },
      { label: 'Điểm dưới trung bình (<5)', v1: (s) => fmtInt(s.lt5Count), v2: (s) => fmtPct(s.lt5Pct, 2), color: '#ee642c' },
      { label: 'Điểm >= 7', v1: (s) => fmtInt(s.gte7Count), v2: (s) => fmtPct(s.gte7Pct, 2), color: '#27397c' },
      { label: 'Mode', v1: (s) => fmtDec(s.mode, 2), v2: () => '', color: '#0f172a' },
      { label: 'Số điểm 10', v1: (s) => fmtInt(s.score10Count), v2: () => '', color: '#ee642c' },
      { label: 'Số điểm 0', v1: (s) => fmtInt(s.score0Count), v2: () => '', color: '#0f172a' },
      { label: 'Số điểm <= 1', v1: (s) => fmtInt(s.lte1Count), v2: (s) => fmtPct(s.lte1Pct, 2), color: '#0f172a' },
    ];

    metricRows.forEach((mr, rIdx) => {
      const ry = ty + 42 + rIdx * rowH;
      ctx.fillStyle = '#27397c';
      ctx.fillRect(tx, ry, labelColW, rowH);
      ctx.strokeStyle = '#cbd5e1';
      ctx.strokeRect(tx, ry, labelColW, rowH);

      ctx.fillStyle = '#ffffff';
      ctx.font = '700 14.5px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(mr.label, tx + 12, ry + rowH / 2);

      sessionStatsList.forEach((item, sIdx) => {
        const sx = tx + labelColW + sIdx * sessColW;
        const halfW = sessColW / 2;
        ctx.fillStyle = rIdx % 2 === 0 ? '#f8fafc' : '#ffffff';
        ctx.fillRect(sx, ry, sessColW, rowH);
        ctx.strokeStyle = '#cbd5e1';
        ctx.strokeRect(sx, ry, halfW, rowH);
        ctx.strokeRect(sx + halfW, ry, halfW, rowH);

        ctx.fillStyle = mr.color;
        ctx.font = '600 15px Inter, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(mr.v1(item.stats), sx + halfW - 10, ry + rowH / 2);
        const val2 = mr.v2(item.stats);
        if (val2) ctx.fillText(val2, sx + sessColW - 10, ry + rowH / 2);
      });
    });

    const chartY = ty + 42 + metricRows.length * rowH + 20;
    const chartH = baseH - chartY - 40;
    const subCanvas = document.createElement('canvas');
    drawMultiSessionOverlayChart(subCanvas, sessionStatsList, { width: tw, height: chartH, scale });
    ctx.drawImage(subCanvas, 0, 0, tw * scale, chartH * scale, tx, chartY, tw, chartH);

    drawExportWatermarkFooter(ctx, baseW, baseH, getCurrentSession());
    ctx.restore();
    triggerCanvasDownload(canvas, `So_Sanh_Cac_Lan_Thi_${slugify(subj)}_Khoi_${grade}`, format === 'svg' ? 'png' : format);
    showToast(`Đã tải ảnh So sánh các lần thi Khối ${grade} (${scale}K)`);
  }

  function exportGroupRankingImage() {
    const { scale, format } = getExportSettings();
    const sess = getCurrentSession();
    const subj = state.currentSubject;
    const subjRecords = sess.records.filter((r) => r.subject === subj);
    const allGrades = getGradesForSubject(sess, subj);

    const baseW = 1380;
    let baseH = 760;

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    if (state.groupStatMode === 'grade_summary') {
      baseH = 170 + allGrades.length * 44 + 54;
      canvas.width = baseW * scale;
      canvas.height = baseH * scale;
      ctx.save();
      ctx.scale(scale, scale);

      ctx.fillStyle = '#f8fafc';
      ctx.fillRect(0, 0, baseW, baseH);

      ctx.fillStyle = '#0f172a';
      ctx.font = '800 22px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(
        `THỐNG KÊ ĐTB & ĐIỂM CAO NHẤT THEO TỪNG KHỐI MÔN ${subj.toUpperCase()} — ${state.centerName}`,
        40,
        28
      );

      const leftRows = Array.from(document.querySelectorAll('#tableGradeAvgAndMax tbody tr'));
      const rightRows = Array.from(document.querySelectorAll('#tableGradeQuality tbody tr'));

      drawGenericTableOnCanvas(
        ctx,
        40,
        82,
        [80, 75, 75, 85, 85, 240],
        ['Khối', 'Dự thi', 'Vắng (x)', 'Điểm TB', 'Cao nhất', 'Thủ khoa Khối'],
        leftRows
      );

      drawGenericTableOnCanvas(
        ctx,
        700,
        82,
        [90, 120, 145, 145, 140],
        ['Khối', 'Điểm 10', '>= 8.0', '>= 7.0', '< 5.0'],
        rightRows
      );

      drawExportWatermarkFooter(ctx, baseW, baseH, sess);
      ctx.restore();
      triggerCanvasDownload(canvas, `Thong_Ke_Khoi_${slugify(subj)}`, format === 'svg' ? 'png' : format);
      showToast(`Đã tải ảnh Thống kê theo Khối (${scale}K)`);
      return;
    }

    const tables = Array.from(document.querySelectorAll('#teacherByGradeTablesWrap table'));
    let totalRows = 0;
    tables.forEach((t) => {
      totalRows += t.querySelectorAll('tbody tr').length + 2;
    });
    baseH = 100 + totalRows * 40 + 54;
    canvas.width = baseW * scale;
    canvas.height = baseH * scale;
    ctx.save();
    ctx.scale(scale, scale);

    ctx.fillStyle = '#f8fafc';
    ctx.fillRect(0, 0, baseW, baseH);

    ctx.fillStyle = '#0f172a';
    ctx.font = '800 22px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(
      `THỐNG KÊ THEO KHỐI LỚP CỦA TỪNG GIÁO VIÊN MÔN ${subj.toUpperCase()} — ${state.centerName}`,
      40,
      26
    );

    let curY = 76;
    const boxes = Array.from(document.querySelectorAll('#teacherByGradeTablesWrap .thpt-rank-box'));
    boxes.forEach((box) => {
      const heading = box.querySelector('h3')?.textContent.trim() || '';
      ctx.fillStyle = '#27397c';
      ctx.font = '800 16px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(heading, 40, curY);
      curY += 26;

      const trs = Array.from(box.querySelectorAll('tbody tr'));
      curY = drawGenericTableOnCanvas(
        ctx,
        40,
        curY,
        [55, 200, 80, 80, 110, 110, 110, 100, 145, 95, 145],
        ['Hạng', 'Giáo viên', 'Dự thi', 'Vắng (x)', 'ĐTB của GV', 'ĐTB Nhóm', 'So với Nhóm', 'Cao nhất', 'Số điểm >=8', 'Điểm 10', 'Dưới TB (<5)'],
        trs
      );
      curY += 24;
    });

    drawExportWatermarkFooter(ctx, baseW, baseH, sess);
    ctx.restore();
    triggerCanvasDownload(canvas, `So_Sanh_GV_Theo_Khoi_${slugify(subj)}`, format === 'svg' ? 'png' : format);
    showToast(`Đã tải ảnh So sánh GV theo Khối (${scale}K)`);
  }

  function drawGenericTableOnCanvas(ctx, x, y, colWidths, headers, domRows) {
    const rh = 38;
    let cx = x;
    headers.forEach((h, i) => {
      ctx.fillStyle = '#27397c';
      ctx.fillRect(cx, y, colWidths[i], rh);
      ctx.strokeStyle = '#1d2b61';
      ctx.strokeRect(cx, y, colWidths[i], rh);
      ctx.fillStyle = '#ffffff';
      ctx.font = '700 13.5px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(h, cx + colWidths[i] / 2, y + rh / 2);
      cx += colWidths[i];
    });

    domRows.forEach((tr, rIdx) => {
      const cells = Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.trim());
      const ry = y + (rIdx + 1) * rh;
      let rx = x;
      cells.forEach((text, cIdx) => {
        ctx.fillStyle = cIdx === 0 ? '#eef1f8' : rIdx % 2 === 0 ? '#f8fafc' : '#ffffff';
        ctx.fillRect(rx, ry, colWidths[cIdx], rh);
        ctx.strokeStyle = '#cbd5e1';
        ctx.strokeRect(rx, ry, colWidths[cIdx], rh);

        ctx.fillStyle = cIdx === 0 ? '#27397c' : cIdx === 4 ? '#ee642c' : '#0f172a';
        ctx.font = cIdx === 0 || cIdx === 1 || cIdx === 4 ? '700 13.5px Inter, sans-serif' : '500 13.5px Inter, sans-serif';
        ctx.textAlign = cIdx === 1 ? 'left' : 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, cIdx === 1 ? rx + 10 : rx + colWidths[cIdx] / 2, ry + rh / 2);
        rx += colWidths[cIdx];
      });
    });

    return y + (domRows.length + 1) * rh;
  }

  function exportTopStudentsImage() {
    const { scale, format } = getExportSettings();
    const sess = getCurrentSession();
    const subj = state.currentSubject;
    const grade = state.filterGrade;
    const topN = Math.max(0, parseInt(state.topN, 10) || 0);
    const { list } = getUnifiedStudentList(sess, subj, topN, state.includeTies, state.filterTeacher, grade);

    const statusTitleMap = {
      ALL: topN > 0 ? `TOP ${topN} HỌC SINH ĐIỂM CAO NHẤT` : 'BẢNG ĐIỂM & XẾP HẠNG HỌC SINH',
      SCORED: topN > 0 ? `TOP ${topN} HỌC SINH DỰ THI` : 'DANH SÁCH HỌC SINH DỰ THI',
      GT9: 'DANH SÁCH HỌC SINH ĐIỂM TRÊN 9 (>= 9.0)',
      LT5: 'DANH SÁCH HỌC SINH ĐIỂM DƯỚI 5 (< 5.0)',
      ABSENT: 'DANH SÁCH HỌC SINH VẮNG THI (X)',
    };
    const titlePrefix = statusTitleMap[state.studentStatusFilter] || 'BẢNG ĐIỂM & XẾP HẠNG HỌC SINH';

    const rowH = 38;
    const baseW = 1360;
    const baseH = 140 + Math.max(list.length, 1) * rowH + 52;

    const canvas = document.createElement('canvas');
    canvas.width = baseW * scale;
    canvas.height = baseH * scale;
    const ctx = canvas.getContext('2d');
    ctx.save();
    ctx.scale(scale, scale);

    ctx.fillStyle = '#f8fafc';
    ctx.fillRect(0, 0, baseW, baseH);

    ctx.fillStyle = '#27397c';
    ctx.font = '800 22px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(
      `${titlePrefix} — MÔN ${subj.toUpperCase()} (KHỐI ${grade}) — ${state.centerName}`,
      40,
      26
    );

    const tx = 40;
    const ty = 74;
    const colWidths = [70, 390, 110, 170, 220, 150, 170];
    const headers = ['HẠNG', 'HỌC SINH', 'KHỐI', 'BỘ MÔN', 'GIÁO VIÊN', 'NGÀY THI', 'ĐIỂM / TT'];

    let cx = tx;
    headers.forEach((h, i) => {
      ctx.fillStyle = '#27397c';
      ctx.fillRect(cx, ty, colWidths[i], 40);
      ctx.strokeStyle = '#1d2b61';
      ctx.strokeRect(cx, ty, colWidths[i], 40);
      ctx.fillStyle = '#ffffff';
      ctx.font = '700 14.5px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(h, cx + colWidths[i] / 2, ty + 20);
      cx += colWidths[i];
    });

    list.forEach((item, rIdx) => {
      const ry = ty + 40 + rIdx * rowH;
      const isAbs = item.isAbsent || item.absent || item.score === null;
      const isLt5 = !isAbs && item.score < 5;
      const isGt9 = !isAbs && item.score >= 9;
      const cells = [
        !isAbs && item.rank !== null ? String(item.rank) : 'KĐ',
        item.name,
        `Khối ${item.grade}`,
        item.subject,
        `GV ${item.teacher}`,
        item.examDate || sess.date || '-',
        isAbs ? 'x (Vắng)' : fmtFixed(item.score, 2),
      ];

      let rx = tx;
      cells.forEach((val, cIdx) => {
        if (isLt5 || isAbs) {
          ctx.fillStyle = cIdx === 0 ? '#fbd5c4' : '#fef2ec';
        } else if (isGt9) {
          ctx.fillStyle = cIdx === 0 ? '#d5dcf0' : '#eef1f8';
        } else {
          ctx.fillStyle = cIdx === 0 ? '#eef1f8' : rIdx % 2 === 0 ? '#f8fafc' : '#ffffff';
        }
        ctx.fillRect(rx, ry, colWidths[cIdx], rowH);
        ctx.strokeStyle = '#cbd5e1';
        ctx.strokeRect(rx, ry, colWidths[cIdx], rowH);

        if ((isLt5 || isAbs) && (cIdx === 1 || cIdx === 6)) {
          ctx.fillStyle = '#ee642c';
        } else if (isGt9 && (cIdx === 1 || cIdx === 6)) {
          ctx.fillStyle = '#27397c';
        } else {
          ctx.fillStyle = cIdx === 0 ? '#27397c' : cIdx === 6 ? '#27397c' : '#0f172a';
        }
        ctx.font = cIdx === 0 || cIdx === 1 || cIdx === 6 ? '700 14.5px Inter, sans-serif' : '500 14px Inter, sans-serif';
        ctx.textAlign = cIdx === 1 ? 'left' : 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(val, cIdx === 1 ? rx + 14 : rx + colWidths[cIdx] / 2, ry + rowH / 2);
        rx += colWidths[cIdx];
      });
    });

    drawExportWatermarkFooter(ctx, baseW, baseH, sess);
    ctx.restore();
    const filePrefix = topN > 0 ? `Top_${topN}` : `Bang_Diem_${state.studentStatusFilter}`;
    triggerCanvasDownload(canvas, `${filePrefix}_${slugify(subj)}_Khoi_${grade}`, format === 'svg' ? 'png' : format);
    showToast(`Đã tải ảnh Bảng điểm & Xếp hạng môn ${subj} Khối ${grade} (${scale}K)`);
  }

  function triggerCanvasDownload(canvas, filenameBase, format) {
    const mime = format === 'jpeg' ? 'image/jpeg' : 'image/png';
    const ext = format === 'jpeg' ? 'jpg' : 'png';
    canvas.toBlob((blob) => {
      if (blob) downloadBlob(blob, `${filenameBase}.${ext}`);
    }, mime, 1.0);
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 300);
  }

  function batchExportAllSubjects() {
    const sess = getCurrentSession();
    if (!sess) return;
    const allowedSubjs = getAllowedSubjects(sess);
    if (!allowedSubjs.length) return;
    const tasks = [];
    allowedSubjs.forEach((subj) => {
      const selectedG = state.overviewSelectedGrades[subj] || getGradesForSubject(sess, subj)[0];
      if (selectedG) tasks.push({ subj, grade: selectedG });
    });
    showToast(`Đang tải ${tasks.length} ảnh phổ điểm 6K...`);
    tasks.forEach((t, i) => {
      setTimeout(() => {
        exportHighResPhoDiemCard(sess, t.subj, 'ALL', t.grade);
      }, i * 380);
    });
  }

  function exportTopStudentsCSV() {
    const sess = getCurrentSession();
    if (!sess) return;
    const topN = Math.max(0, parseInt(state.topN, 10) || 0);
    const lines = ['\uFEFFHẠNG,HỌC SINH,KHỐI,BỘ MÔN,GIÁO VIÊN,NGÀY THI,ĐIỂM / TT,ĐỢT THI'];

    const { list } = getUnifiedStudentList(
      sess,
      state.currentSubject,
      topN,
      state.includeTies,
      state.filterTeacher,
      state.filterGrade
    );
    list.forEach((r) => {
      const isAbs = r.isAbsent || r.absent || r.score === null;
      const rankStr = !isAbs && r.rank !== null ? r.rank : 'KĐ';
      const scoreStr = isAbs ? 'x' : r.score;
      lines.push(
        `${rankStr},"${r.name}","${r.grade}","${r.subject}","${r.teacher}","${r.examDate || sess.date || ''}",${scoreStr},"${sess.name}"`
      );
    });

    const filePrefix = topN > 0 ? `Top_${topN}` : `Bang_Diem_${state.studentStatusFilter}`;
    downloadBlob(
      new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' }),
      `${filePrefix}_${slugify(state.currentSubject)}_Khoi_${state.filterGrade}.csv`
    );
    showToast('Đã xuất file CSV Bảng điểm & Xếp hạng');
  }

  // ============================================================================
  // DRAG & DROP FILE UPLOAD (Auto-recognizes L1.xlsx, L2.xlsx, L3.xlsx, L4.xlsx...)
  // ============================================================================
  function extractAdminExamNumber(filename) {
    if (!filename) return null;
    const base = filename.replace(/\.[^.]+$/, '').trim();
    const matchL = base.match(/^L(\d+)$/i) || base.match(/^Lan[_\s-]*(\d+)$/i) || base.match(/^Lần[_\s-]*(\d+)$/i);
    if (matchL) return parseInt(matchL[1], 10);
    return null;
  }

  function readSingleFileToRows(file) {
    return new Promise((resolve, reject) => {
      const ext = file.name.split('.').pop().toLowerCase();
      if (ext === 'xlsx' || ext === 'xls') {
        const reader = new FileReader();
        reader.onload = (e) => {
          try {
            const rows = parseWorkbookBufferToRows(e.target.result);
            resolve(rows);
          } catch (err) {
            reject(err);
          }
        };
        reader.onerror = () => reject(new Error('Không đọc được file Excel'));
        reader.readAsArrayBuffer(file);
      } else {
        const reader = new FileReader();
        reader.onload = (e) => resolve(parseCSVToRows(e.target.result));
        reader.onerror = () => reject(new Error('Không đọc được file CSV'));
        reader.readAsText(file, 'utf-8');
      }
    });
  }

  async function handleIncomingFiles(fileList) {
    if (!isAdminUser()) {
      showToast('Chỉ tài khoản ADMIN mới được phép kéo thả hoặc tải file dữ liệu!');
      return;
    }
    if (!fileList || fileList.length === 0) return;
    const files = Array.from(fileList);

    // Check if files are L1, L2, L3, L4... or if multiple files were selected
    if (files.length === 1 && extractAdminExamNumber(files[0].name) === null) {
      try {
        const rows = await readSingleFileToRows(files[0]);
        openUploadSessionModal(rows, files[0].name);
      } catch (err) {
        showToast('Lỗi đọc file: ' + err.message);
      }
      return;
    }

    // Auto-import L1, L2, L3, L4... (or batch files) directly into top dropdown!
    let importedNames = [];
    let lastAddedSession = null;
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      try {
        const rows = await readSingleFileToRows(file);
        const parsed = parseCenterRows(rows);
        if (parsed.totalRecords === 0) continue;

        const examNum = extractAdminExamNumber(file.name);
        if (examNum !== null) {
          const sessObj = upsertAdminSessionFromParsed(examNum, file.name, parsed);
          if (sessObj) {
            lastAddedSession = sessObj;
            importedNames.push(`Lần thi ${examNum}`);
          }
        } else {
          const nextNum = state.sessions.length + 1;
          const newSess = {
            id: 'sess-' + Date.now() + '-' + i,
            name: `Lần thi ${nextNum}`,
            shortName: `Lần ${nextNum}`,
            fileName: file.name,
            examOrder: nextNum,
            date: new Date().toLocaleDateString('vi-VN'),
            records: parsed.records,
            subjects: parsed.subjects,
          };
          state.sessions.push(newSess);
          lastAddedSession = newSess;
          importedNames.push(newSess.name);
        }
      } catch (err) {
        showToast(`Lỗi đọc file ${file.name}: ${err.message}`);
      }
    }

    if (lastAddedSession) {
      state.currentSessionId = lastAddedSession.id;
      ensureValidGradeAndTeacher();
      saveSessionsToStorage();
      refreshAllUI(true);
      showToast(`Đã tự động nhận diện & nạp: ${importedNames.join(', ')}`);
    } else {
      showToast('Không tìm thấy dữ liệu hợp lệ trong file tải lên');
    }
  }

  function handleIncomingFile(file) {
    if (file) handleIncomingFiles([file]);
  }

  function openUploadSessionModal(rows, filename) {
    const parsed = parseCenterRows(rows);
    if (parsed.totalRecords === 0) {
      showToast('File không đúng định dạng mẫu danh sách của trung tâm');
      return;
    }

    state.pendingUploadRows = parsed;
    state.pendingUploadFileName = filename;
    const absentCnt = parsed.records.filter((r) => r.absent).length;

    document.getElementById('uploadFileSummaryBox').innerHTML = `
      <div><b>File:</b> ${escapeHtml(filename)}</div>
      <div style="margin-top:4px;">
        • Tổng danh sách: <b>${fmtInt(parsed.totalRecords)}</b> HS (${fmtInt(parsed.validScoreCount)} có điểm • <b>${fmtInt(absentCnt)}</b> vắng thi x)<br/>
        • Bộ môn (${parsed.subjects.length}): <b>${parsed.subjects.map(escapeHtml).join(', ')}</b>
      </div>
    `;

    const blankNotice = document.getElementById('blankScoreNotice');
    if (parsed.validScoreCount === 0) {
      blankNotice.style.display = 'block';
      document.getElementById('autoFillMockScoresCheckbox').checked = true;
    } else {
      blankNotice.style.display = 'none';
    }

    const nextIdx = state.sessions.length + 1;
    document.getElementById('newSessionNameInput').value = `Lần thi ${nextIdx}`;
    document.getElementById('newSessionShortInput').value = `Lần ${nextIdx}`;
    document.getElementById('uploadSessionModal').classList.add('open');
  }

  function confirmUploadSession() {
    const parsed = state.pendingUploadRows;
    if (!parsed) return;

    let finalRecords = parsed.records;
    const autoFill = document.getElementById('autoFillMockScoresCheckbox')?.checked;
    if (parsed.validScoreCount === 0 && autoFill) {
      finalRecords = fillMockScoresForRecords(finalRecords);
    }

    const mode = document.getElementById('uploadActionMode').value;
    const todayStr = new Date().toLocaleDateString('vi-VN');

    if (mode === 'replace') {
      const cur = getCurrentSession();
      if (cur) {
        cur.records = finalRecords;
        cur.subjects = parsed.subjects;
        if (state.pendingUploadFileName) cur.fileName = state.pendingUploadFileName;
        showToast(`Đã cập nhật "${cur.name}"`);
      }
    } else {
      const nextOrder = state.sessions.length + 1;
      const name = cleanSessionLabel(document.getElementById('newSessionNameInput').value.trim()) || `Lần thi ${nextOrder}`;
      const shortName = cleanSessionLabel(document.getElementById('newSessionShortInput').value.trim()) || `Lần ${nextOrder}`;
      const newSess = {
        id: 'sess-' + Date.now(),
        name,
        shortName,
        fileName: state.pendingUploadFileName || '',
        examOrder: nextOrder,
        date: todayStr,
        records: finalRecords,
        subjects: parsed.subjects,
      };
      state.sessions.push(newSess);
      state.currentSessionId = newSess.id;
      showToast(`Đã thêm "${name}"`);
    }

    ensureValidGradeAndTeacher();
    saveSessionsToStorage();
    document.getElementById('uploadSessionModal').classList.remove('open');
    refreshAllUI(true);
  }

  // ============================================================================
  // VIEW MODE & REFRESH
  // ============================================================================
  function updateViewModeVisibility() {
    const v = state.viewMode;
    document.getElementById('sectionPhoDiem').style.display = v === 'all' || v === 'phodiem' ? '' : 'none';
    document.getElementById('sectionMultiSession').style.display = v === 'all' || v === 'multisession' ? '' : 'none';
    document.getElementById('sectionGroupRanking').style.display = v === 'all' || v === 'grouprank' ? '' : 'none';
    document.getElementById('sectionTopStudents').style.display =
      v === 'all' || v === 'topstudents' || v === 'absent' ? '' : 'none';
    const allSubjSec = document.getElementById('sectionAllSubjectsOverview');
    if (allSubjSec) allSubjSec.style.display = v === 'all' || v === 'allsubjects' ? '' : 'none';
  }

  function syncStickyReportActionBars() {
    const qfb = document.querySelector('.quick-filter-banner');
    let stickyTop = 8;
    if (qfb && qfb.offsetParent !== null) {
      const qfbTop = parseFloat(window.getComputedStyle(qfb).top) || 8;
      stickyTop = Math.round(qfbTop + qfb.offsetHeight - 1);
    }
    document.documentElement.style.setProperty('--sticky-action-bar-top', `${stickyTop}px`);

    let anyBarStuck = false;
    const wrappers = document.querySelectorAll('.thpt-report-wrapper');
    wrappers.forEach((wrap) => {
      if (wrap.style.display === 'none') return;
      const bar = wrap.querySelector('.report-action-bar');
      if (!bar) return;
      const barRect = bar.getBoundingClientRect();
      const wrapRect = wrap.getBoundingClientRect();
      const isStuck = barRect.top <= stickyTop + 2 && wrapRect.bottom > barRect.bottom + 4;
      bar.classList.toggle('is-stuck', isStuck);
      if (isStuck) anyBarStuck = true;
    });

    if (qfb) {
      qfb.classList.toggle('has-stuck-bar', anyBarStuck);
    }
  }

  function refreshAllUI(animateChart = false) {
    if (!isAuthenticated()) return;
    ensureValidGradeAndTeacher();
    renderSessionPills();
    renderSubjectTabs();
    renderTeacherAndGradeFilters();

    const sess = getCurrentSession();
    const records = getFilteredRecords(sess, state.currentSubject, state.filterTeacher, state.filterGrade);
    const stats = computeStatistics(records, state.binStep);

    updateTHPTMainSection(stats);

    if (animateChart) {
      triggerChartAnimation(stats);
    } else {
      drawTHPTChartOnCanvas(document.getElementById('phoDiemCanvas'), stats, 1, -1);
    }
    renderSelectedBinInlinePanel(stats);

    renderMultiSessionComparison();
    renderGroupRankingSection();
    renderTopStudentsSection();
    renderAbsentAndSearchSection();
    renderAllSubjectsOverview();
    syncStickyReportActionBars();
  }

  function showToast(msg) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const item = document.createElement('div');
    item.className = 'toast-item';
    item.innerHTML = `<span style="width:7px; height:7px; border-radius:50%; background:#ee642c;"></span><span>${escapeHtml(msg)}</span>`;
    container.appendChild(item);
    setTimeout(() => {
      item.style.opacity = '0';
      item.style.transition = 'opacity 0.2s ease';
      setTimeout(() => item.remove(), 220);
    }, 3000);
  }

  function escapeHtml(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ============================================================================
  // HIGH-SECURITY LOGIN, BRUTE-FORCE GUARD & SESSION CONTROLLER
  // ============================================================================
  let lockoutTimerId = null;

  function getLockoutState() {
    try {
      const raw = localStorage.getItem(AUTH_LOCKOUT_KEY);
      if (!raw) return { failed: 0, lockedUntil: 0 };
      const parsed = JSON.parse(raw);
      return {
        failed: Number(parsed.failed || 0),
        lockedUntil: Number(parsed.lockedUntil || 0),
      };
    } catch (e) {
      return { failed: 0, lockedUntil: 0 };
    }
  }

  function saveLockoutState(failed, lockedUntil) {
    try {
      localStorage.setItem(AUTH_LOCKOUT_KEY, JSON.stringify({ failed, lockedUntil }));
    } catch (e) {
      // ignore
    }
  }

  function setAuthErrorMessage(msg) {
    const box = document.getElementById('authErrorBox');
    if (!box) return;
    if (!msg) {
      box.style.display = 'none';
      box.textContent = '';
    } else {
      box.style.display = 'block';
      box.innerHTML = msg;
    }
  }

  function checkAndEnforceLockoutUI() {
    const submitBtn = document.getElementById('btnSubmitAuthLogin');
    const st = getLockoutState();
    const now = Date.now();
    if (st.lockedUntil > now) {
      const remSec = Math.ceil((st.lockedUntil - now) / 1000);
      if (submitBtn) submitBtn.disabled = true;
      setAuthErrorMessage(
        `<i class="fa-solid fa-lock"></i> Nhập sai quá ${PRIVATE_AUTH_VAULT.settings.maxFailedAttempts} lần. Hệ thống tạm khóa trong <b>${remSec}s</b>!`
      );
      if (!lockoutTimerId) {
        lockoutTimerId = setInterval(() => {
          const cur = getLockoutState();
          if (cur.lockedUntil <= Date.now()) {
            clearInterval(lockoutTimerId);
            lockoutTimerId = null;
            saveLockoutState(0, 0);
            if (submitBtn) submitBtn.disabled = false;
            setAuthErrorMessage('');
          } else {
            const r = Math.ceil((cur.lockedUntil - Date.now()) / 1000);
            setAuthErrorMessage(
              `<i class="fa-solid fa-lock"></i> Nhập sai quá ${PRIVATE_AUTH_VAULT.settings.maxFailedAttempts} lần. Hệ thống tạm khóa trong <b>${r}s</b>!`
            );
          }
        }, 500);
      }
      return true;
    }
    if (submitBtn) submitBtn.disabled = false;
    return false;
  }

  function syncAuthRoleUI() {
    const isAuth = isAuthenticated();
    const isAdmin = isAdminUser();
    const overlay = document.getElementById('authLoginOverlay');
    const adminUploadWrap = document.getElementById('adminUploadControlWrap');
    const globalOverlay = document.getElementById('globalDropOverlay');
    const resetBtn = document.getElementById('btnResetDemoData');
    const delBtn = document.getElementById('btnDeleteCurrentSession');

    if (isAuth) {
      document.body.classList.add('auth-unlocked');
      if (overlay) overlay.style.display = 'none';
    } else {
      document.body.classList.remove('auth-unlocked');
      if (overlay) overlay.style.display = 'flex';
    }

    // Strictly hide file drag-and-drop / upload zone for non-ADMIN
    if (adminUploadWrap) {
      adminUploadWrap.style.display = isAdmin ? '' : 'none';
    }
    if (!isAdmin && globalOverlay) {
      globalOverlay.classList.remove('active');
    }
    if (resetBtn) {
      resetBtn.style.display = isAdmin ? '' : 'none';
    }
    if (delBtn) {
      delBtn.style.display = isAdmin && state.sessions.length > 1 ? 'inline-flex' : 'none';
    }

    // Update Sidebar User Badge
    const nameEl = document.getElementById('authUserDisplayName');
    const roleEl = document.getElementById('authUserRoleBadge');
    const avatarEl = document.getElementById('authUserAvatar');
    if (isAuth && state.currentUser) {
      if (nameEl) nameEl.textContent = state.currentUser.displayName || state.currentUser.username;
      if (roleEl) {
        roleEl.textContent = isAdmin
          ? 'ADMIN • Toàn bộ môn'
          : `USER • ${(state.currentUser.subjects || []).join(', ')}`;
      }
      if (avatarEl) {
        avatarEl.classList.toggle('is-admin', isAdmin);
        avatarEl.innerHTML = isAdmin
          ? '<i class="fa-solid fa-user-shield"></i>'
          : '<i class="fa-solid fa-chalkboard-user"></i>';
      }
    }
  }

  function getOrCreateDeviceId() {
    try {
      let devId = localStorage.getItem(DEVICE_ID_KEY);
      if (!devId || typeof devId !== 'string' || devId.length < 8) {
        devId = 'mhdev_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 11);
        localStorage.setItem(DEVICE_ID_KEY, devId);
      }
      return devId;
    } catch (e) {
      if (!window.__mhFallbackDeviceId) {
        window.__mhFallbackDeviceId = 'mhdev_mem_' + Math.random().toString(36).slice(2, 11);
      }
      return window.__mhFallbackDeviceId;
    }
  }

  function signDeviceRecord(username, deviceId, exp) {
    return computeSecureDigest(`DEV_SLOT::${username}|${deviceId}|${exp}`);
  }

  function getActiveDevicesStore() {
    try {
      const raw = localStorage.getItem(ACTIVE_DEVICES_KEY);
      if (!raw) return {};
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (e) {
      return {};
    }
  }

  function saveActiveDevicesStore(store) {
    try {
      localStorage.setItem(ACTIVE_DEVICES_KEY, JSON.stringify(store || {}));
    } catch (e) {
      // ignore
    }
  }

  function pruneAndGetActiveDevicesForUser(username) {
    const uname = String(username || '').trim().toLowerCase();
    if (!uname) return [];
    const store = getActiveDevicesStore();
    const rawList = Array.isArray(store[uname]) ? store[uname] : [];
    const now = Date.now();
    const dedupMap = new Map();

    rawList.forEach((item) => {
      if (!item || !item.deviceId || !item.exp || !item.sig) return;
      const expNum = Number(item.exp);
      if (!isFinite(expNum) || now > expNum) return;
      const expectedSig = signDeviceRecord(uname, item.deviceId, expNum);
      if (!constantTimeEquals(item.sig, expectedSig)) return;
      const existing = dedupMap.get(item.deviceId);
      if (!existing || existing.exp < expNum) {
        dedupMap.set(item.deviceId, {
          deviceId: String(item.deviceId),
          lastActive: Number(item.lastActive) || now,
          exp: expNum,
          sig: item.sig,
        });
      }
    });

    const cleaned = Array.from(dedupMap.values());
    store[uname] = cleaned;
    saveActiveDevicesStore(store);
    return cleaned;
  }

  function canDeviceLoginForUser(username) {
    const uname = String(username || '').trim().toLowerCase();
    const maxDevices = Math.max(1, Number(PRIVATE_AUTH_VAULT.settings.maxDevicesPerAccount) || 7);
    const myDeviceId = getOrCreateDeviceId();
    const activeList = pruneAndGetActiveDevicesForUser(uname);
    const alreadyRegistered = activeList.some((d) => d.deviceId === myDeviceId);
    if (alreadyRegistered) {
      return { allowed: true, activeCount: activeList.length, maxDevices };
    }
    if (activeList.length >= maxDevices) {
      return { allowed: false, activeCount: activeList.length, maxDevices };
    }
    return { allowed: true, activeCount: activeList.length, maxDevices };
  }

  function registerDeviceSessionForUser(username, exp) {
    const uname = String(username || '').trim().toLowerCase();
    if (!uname) return;
    const myDeviceId = getOrCreateDeviceId();
    const maxDevices = Math.max(1, Number(PRIVATE_AUTH_VAULT.settings.maxDevicesPerAccount) || 7);
    const activeList = pruneAndGetActiveDevicesForUser(uname).filter((d) => d.deviceId !== myDeviceId);
    activeList.push({
      deviceId: myDeviceId,
      lastActive: Date.now(),
      exp,
      sig: signDeviceRecord(uname, myDeviceId, exp),
    });
    const trimmed = activeList.slice(-maxDevices);
    const store = getActiveDevicesStore();
    store[uname] = trimmed;
    saveActiveDevicesStore(store);
  }

  function unregisterDeviceSessionForUser(username) {
    const uname = String(username || '').trim().toLowerCase();
    if (!uname) return;
    const myDeviceId = getOrCreateDeviceId();
    const activeList = pruneAndGetActiveDevicesForUser(uname).filter((d) => d.deviceId !== myDeviceId);
    const store = getActiveDevicesStore();
    store[uname] = activeList;
    saveActiveDevicesStore(store);
  }

  function saveSignedAuthSession(userObj) {
    const timeoutMinutes = Number(PRIVATE_AUTH_VAULT.settings.sessionTimeoutMinutes) || 120;
    const timeoutMs = timeoutMinutes * 60 * 1000;
    const exp = Date.now() + timeoutMs;
    const sig = signSessionPayload(userObj, exp);
    const payload = {
      username: userObj.username,
      role: userObj.role,
      displayName: userObj.displayName,
      subjects: userObj.subjects,
      deviceId: getOrCreateDeviceId(),
      exp,
      sig,
    };
    try {
      sessionStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(payload));
    } catch (e) {
      // ignore
    }
    registerDeviceSessionForUser(userObj.username, exp);
  }

  function restoreSignedAuthSession() {
    try {
      const raw = sessionStorage.getItem(AUTH_SESSION_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || !parsed.username || !parsed.exp || !parsed.sig) return null;
      if (Date.now() > Number(parsed.exp)) {
        sessionStorage.removeItem(AUTH_SESSION_KEY);
        unregisterDeviceSessionForUser(parsed.username);
        return null;
      }
      // Verify against vault account and signature
      const vaultAcc = PRIVATE_AUTH_VAULT.accounts.find((a) => a.username === parsed.username);
      if (!vaultAcc) {
        sessionStorage.removeItem(AUTH_SESSION_KEY);
        return null;
      }
      const expectedSig = signSessionPayload(vaultAcc, parsed.exp);
      if (!constantTimeEquals(parsed.sig, expectedSig)) {
        sessionStorage.removeItem(AUTH_SESSION_KEY);
        return null;
      }
      // Check device concurrency slot
      const devCheck = canDeviceLoginForUser(vaultAcc.username);
      if (!devCheck.allowed) {
        sessionStorage.removeItem(AUTH_SESSION_KEY);
        return null;
      }
      return {
        username: vaultAcc.username,
        role: vaultAcc.role,
        displayName: vaultAcc.displayName,
        subjects: vaultAcc.subjects.slice(),
      };
    } catch (e) {
      return null;
    }
  }

  function logoutCurrentUser(reasonMsg = '') {
    const prevUsername = state.currentUser?.username;
    state.currentUser = null;
    try {
      sessionStorage.removeItem(AUTH_SESSION_KEY);
    } catch (e) {
      // ignore
    }
    if (prevUsername) {
      unregisterDeviceSessionForUser(prevUsername);
    }
    closeBinStudentsModal();
    syncAuthRoleUI();
    const uInput = document.getElementById('authUsernameInput');
    const pInput = document.getElementById('authPasswordInput');
    if (pInput) pInput.value = '';
    if (reasonMsg) {
      setAuthErrorMessage(reasonMsg);
    } else {
      setAuthErrorMessage('');
    }
    setTimeout(() => uInput?.focus(), 60);
  }

  function initAuthenticationSystem() {
    // 1. Try restoring signed session from sessionStorage
    const restored = restoreSignedAuthSession();
    if (restored) {
      state.currentUser = restored;
      saveSignedAuthSession(restored);
    }

    syncAuthRoleUI();
    checkAndEnforceLockoutUI();

    // 2. Bind Login Form
    const form = document.getElementById('authLoginForm');
    const uInput = document.getElementById('authUsernameInput');
    const pInput = document.getElementById('authPasswordInput');
    const eyeBtn = document.getElementById('btnToggleAuthPassword');

    eyeBtn?.addEventListener('click', () => {
      if (!pInput) return;
      const isPwd = pInput.type === 'password';
      pInput.type = isPwd ? 'text' : 'password';
      eyeBtn.innerHTML = isPwd ? '<i class="fa-regular fa-eye-slash"></i>' : '<i class="fa-regular fa-eye"></i>';
    });

    form?.addEventListener('submit', (e) => {
      e.preventDefault();
      if (checkAndEnforceLockoutUI()) return;

      const uname = String(uInput?.value || '').trim().toLowerCase();
      const pwd = String(pInput?.value || '');
      if (!uname || !pwd) {
        setAuthErrorMessage('Vui lòng nhập đầy đủ tài khoản và mật khẩu!');
        return;
      }

      const matched = PRIVATE_AUTH_VAULT.accounts.find((acc) => {
        const isUserMatch = acc.username === uname || (Array.isArray(acc.aliases) && acc.aliases.includes(uname));
        if (!isUserMatch) return false;
        const candidateDigest = computeSecureDigest(`${acc.username}::${pwd}`);
        return constantTimeEquals(acc.passwordDigest, candidateDigest);
      });

      if (!matched) {
        const curLock = getLockoutState();
        const nextFailed = curLock.failed + 1;
        const maxFail = PRIVATE_AUTH_VAULT.settings.maxFailedAttempts || 5;
        if (nextFailed >= maxFail) {
          const lockUntil = Date.now() + (PRIVATE_AUTH_VAULT.settings.lockoutDurationSeconds || 60) * 1000;
          saveLockoutState(nextFailed, lockUntil);
          checkAndEnforceLockoutUI();
        } else {
          saveLockoutState(nextFailed, 0);
          setAuthErrorMessage(
            `<i class="fa-solid fa-triangle-exclamation"></i> Sai tài khoản hoặc mật khẩu! (Còn <b>${maxFail - nextFailed}</b> lần thử)`
          );
        }
        if (pInput) {
          pInput.value = '';
          pInput.focus();
        }
        return;
      }

      // Enforce maximum 2 concurrent devices per account
      const deviceCheck = canDeviceLoginForUser(matched.username);
      if (!deviceCheck.allowed) {
        setAuthErrorMessage(
          `<i class="fa-solid fa-laptop-medical"></i> Tài khoản <b>${escapeHtml(matched.username)}</b> đã đăng nhập đủ giới hạn tối đa <b>${deviceCheck.maxDevices} thiết bị</b>! Vui lòng đăng xuất ở thiết bị khác trước.`
        );
        return;
      }

      // Login success!
      saveLockoutState(0, 0);
      setAuthErrorMessage('');
      state.currentUser = {
        username: matched.username,
        role: matched.role,
        displayName: matched.displayName,
        subjects: matched.subjects.slice(),
      };
      state.currentSubject = null;
      state.filterTeacher = 'ALL';
      saveSignedAuthSession(state.currentUser);
      syncAuthRoleUI();
      ensureValidGradeAndTeacher();
      updateViewModeVisibility();
      refreshAllUI(true);
      showToast(`Xin chào ${state.currentUser.displayName} (${state.currentUser.role})`);
    });

    // 3. Bind Logout Button
    document.getElementById('btnLogoutAuth')?.addEventListener('click', () => {
      logoutCurrentUser();
      showToast('Đã đăng xuất khỏi hệ thống');
    });

    // 4. Activity heartbeat + 2-Hour (120-Minute) Inactivity Auto-Logout Guard
    let lastActivityBumpTs = Date.now();
    const bumpActivity = () => {
      if (!isAuthenticated()) return;
      const now = Date.now();
      if (now - lastActivityBumpTs >= 10000) {
        lastActivityBumpTs = now;
        saveSignedAuthSession(state.currentUser);
      }
    };
    ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'].forEach((evtName) => {
      window.addEventListener(evtName, bumpActivity, { passive: true });
    });

    setInterval(() => {
      if (!isAuthenticated()) return;
      if (!restoreSignedAuthSession()) {
        logoutCurrentUser(
          '<i class="fa-solid fa-clock"></i> Đã tự động đăng xuất sau 2 tiếng không hoạt động (hoặc phiên đã kết thúc)!'
        );
      }
    }, 10000);

    // 5. Anti-Tamper DOM Guard (Prevents bypassing login overlay via DevTools)
    const guardObserver = new MutationObserver(() => {
      if (!isAuthenticated()) {
        if (document.body.classList.contains('auth-unlocked')) {
          document.body.classList.remove('auth-unlocked');
        }
        const ov = document.getElementById('authLoginOverlay');
        if (ov && ov.style.display === 'none') {
          ov.style.display = 'flex';
        }
      }
    });
    guardObserver.observe(document.body, { attributes: true, attributeFilter: ['class'] });

    // 6. DevTools & Source Inspection Guard for Non-Admin Users
    if (PRIVATE_AUTH_VAULT.settings.protectDevToolsForUser) {
      window.addEventListener('contextmenu', (e) => {
        if (!isAdminUser()) {
          e.preventDefault();
        }
      });
      window.addEventListener('keydown', (e) => {
        if (isAdminUser()) return;
        const k = (e.key || '').toUpperCase();
        if (
          k === 'F12' ||
          (e.ctrlKey && e.shiftKey && (k === 'I' || k === 'J' || k === 'C')) ||
          (e.ctrlKey && k === 'U')
        ) {
          e.preventDefault();
          e.stopPropagation();
        }
      });
    }
  }

  // ============================================================================
  // BIND EVENTS
  // ============================================================================
  function bindEvents() {
    document.getElementById('centerNameInput')?.addEventListener('input', (e) => {
      state.centerName = e.target.value.trim() || 'TRUNG TÂM MINH HOÀNG';
      localStorage.setItem(CENTER_NAME_KEY, state.centerName);
      refreshAllUI(false);
    });

    document.getElementById('btnResetDemoData')?.addEventListener('click', () => resetToDemoSessions(true));

    document.getElementById('btnDownloadBlankTemplate')?.addEventListener('click', () => {
      const content = '\uFEFF' + (window.CENTER_SAMPLE_DATA?.template_blank || '');
      downloadBlob(new Blob([content], { type: 'text/csv;charset=utf-8' }), 'mau_diem_trung_tam_minh_hoang.csv');
      showToast('Đã tải file mẫu trống');
    });

    document.getElementById('btnDownloadSampleFilled')?.addEventListener('click', () => {
      const latestCsv = window.CENTER_SAMPLE_DATA?.sessions?.[0]?.csv || '';
      downloadBlob(new Blob(['\uFEFF' + latestCsv], { type: 'text/csv;charset=utf-8' }), 'diem_thi_L1_minh_hoang.csv');
      showToast('Đã tải file điểm L1 mẫu');
    });

    // Top Session Dropdown (#topSessionDropdown)
    document.getElementById('topSessionDropdown')?.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val === '__COMPARE_ALL__') {
        state.viewMode = 'multisession';
        document.querySelectorAll('#viewModeTabs .view-mode-btn').forEach((b) => {
          b.classList.toggle('active', b.getAttribute('data-view') === 'multisession');
        });
        updateViewModeVisibility();
        refreshAllUI(true);
        return;
      }
      state.currentSessionId = val;
      if (state.viewMode === 'multisession') {
        state.viewMode = 'all';
        document.querySelectorAll('#viewModeTabs .view-mode-btn').forEach((b) => {
          b.classList.toggle('active', b.getAttribute('data-view') === 'all');
        });
        updateViewModeVisibility();
      }
      ensureValidGradeAndTeacher();
      refreshAllUI(true);
    });

    // Top Quick Action Buttons
    document.getElementById('btnTopViewPhoDiem')?.addEventListener('click', () => {
      state.viewMode = 'all';
      document.querySelectorAll('#viewModeTabs .view-mode-btn').forEach((b) => {
        b.classList.toggle('active', b.getAttribute('data-view') === 'all');
      });
      updateViewModeVisibility();
      refreshAllUI(true);
      document.getElementById('sectionPhoDiem')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    document.getElementById('btnTopViewScoreList')?.addEventListener('click', () => {
      state.viewMode = 'absent';
      state.studentStatusFilter = 'ALL';
      const statusSel = document.getElementById('studentStatusFilter');
      if (statusSel) statusSel.value = 'ALL';
      document.querySelectorAll('#viewModeTabs .view-mode-btn').forEach((b) => {
        b.classList.toggle('active', b.getAttribute('data-view') === 'absent');
      });
      updateViewModeVisibility();
      refreshAllUI(false);
      document.getElementById('sectionAbsentAndSearch')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    document.getElementById('btnTopCompareSessions')?.addEventListener('click', () => {
      state.viewMode = 'multisession';
      document.querySelectorAll('#viewModeTabs .view-mode-btn').forEach((b) => {
        b.classList.toggle('active', b.getAttribute('data-view') === 'multisession');
      });
      updateViewModeVisibility();
      refreshAllUI(true);
      document.getElementById('sectionMultiSession')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    document.getElementById('btnDeleteCurrentSession')?.addEventListener('click', () => {
      if (state.sessions.length > 1) {
        deleteSession(state.currentSessionId);
      }
    });

    const fileInput = document.getElementById('fileInputHidden');
    const dropzone = document.getElementById('dropzoneArea');
    const globalOverlay = document.getElementById('globalDropOverlay');

    dropzone?.addEventListener('click', () => {
      if (!isAdminUser()) return;
      fileInput?.click();
    });
    document.getElementById('btnBrowseFile')?.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!isAdminUser()) return;
      fileInput?.click();
    });

    fileInput?.addEventListener('change', (e) => {
      if (!isAdminUser()) return;
      if (e.target.files?.length) handleIncomingFiles(e.target.files);
      fileInput.value = '';
    });

    let dragCounter = 0;
    window.addEventListener('dragenter', (e) => {
      e.preventDefault();
      if (!isAdminUser()) return;
      dragCounter++;
      globalOverlay?.classList.add('active');
    });
    window.addEventListener('dragleave', (e) => {
      e.preventDefault();
      if (!isAdminUser()) return;
      dragCounter--;
      if (dragCounter <= 0) {
        dragCounter = 0;
        globalOverlay?.classList.remove('active');
      }
    });
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => {
      e.preventDefault();
      dragCounter = 0;
      globalOverlay?.classList.remove('active');
      if (!isAdminUser()) {
        if (isAuthenticated()) {
          showToast('Tài khoản USER chỉ có quyền xem, không được kéo thả file dữ liệu!');
        }
        return;
      }
      if (e.dataTransfer?.files?.length) handleIncomingFiles(e.dataTransfer.files);
    });

    document.getElementById('btnCloseUploadModal')?.addEventListener('click', () => {
      document.getElementById('uploadSessionModal').classList.remove('open');
    });
    document.getElementById('btnCancelUploadModal')?.addEventListener('click', () => {
      document.getElementById('uploadSessionModal').classList.remove('open');
    });
    document.getElementById('btnCloseBinModal')?.addEventListener('click', () => {
      closeBinStudentsModal();
    });
    document.getElementById('binStudentsModal')?.addEventListener('click', (e) => {
      if (e.target.id === 'binStudentsModal') {
        closeBinStudentsModal();
      }
    });
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeBinStudentsModal();
        document.getElementById('uploadSessionModal')?.classList.remove('open');
      }
    });
    document.getElementById('uploadActionMode')?.addEventListener('change', (e) => {
      const isNew = e.target.value === 'new';
      document.getElementById('newSessionNameGroup').style.display = isNew ? 'block' : 'none';
      document.getElementById('newSessionShortGroup').style.display = isNew ? 'block' : 'none';
    });
    document.getElementById('btnConfirmUploadSession')?.addEventListener('click', confirmUploadSession);

    document.querySelectorAll('.bin-step-pill').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.bin-step-pill').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.binStep = parseFloat(btn.getAttribute('data-step')) || 0.5;
        refreshAllUI(true);
      });
    });

    document.getElementById('toggleBellCurve')?.addEventListener('change', (e) => {
      state.showBellCurve = e.target.checked;
      refreshAllUI(false);
    });

    function syncSidebarToggleLabel() {
      const txtEl = document.getElementById('toggleSidebarBtnText');
      if (!txtEl) return;
      if (window.innerWidth <= 960) {
        txtEl.textContent = 'Menu';
      } else {
        const isCollapsed = document.body.classList.contains('sidebar-collapsed');
        txtEl.textContent = isCollapsed ? 'Hiện menu' : 'Ẩn menu';
      }
    }

    function toggleSidebar() {
      if (window.innerWidth <= 960) {
        document.body.classList.toggle('sidebar-mobile-open');
      } else {
        document.body.classList.toggle('sidebar-collapsed');
        setTimeout(() => refreshAllUI(false), 250);
      }
      syncSidebarToggleLabel();
    }

    document.getElementById('btnToggleSidebar')?.addEventListener('click', toggleSidebar);
    document.getElementById('btnCloseSidebar')?.addEventListener('click', toggleSidebar);
    document.getElementById('sidebarBackdrop')?.addEventListener('click', () => {
      document.body.classList.remove('sidebar-mobile-open');
      syncSidebarToggleLabel();
    });
    syncSidebarToggleLabel();

    document.querySelectorAll('#viewModeTabs .view-mode-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (window.innerWidth <= 960) {
          document.body.classList.remove('sidebar-mobile-open');
        }
        document.querySelectorAll('#viewModeTabs .view-mode-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.viewMode = btn.getAttribute('data-view') || 'all';
        updateViewModeVisibility();
        refreshAllUI(true);
      });
    });

    document.querySelectorAll('#groupStatModeTabs .sub-nav-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('#groupStatModeTabs .sub-nav-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.groupStatMode = btn.getAttribute('data-gmode') || 'teacher_by_grade';
        renderGroupRankingSection();
      });
    });

    document.getElementById('compareGradeFilter')?.addEventListener('change', (e) => {
      state.compareGradeFilter = e.target.value;
      renderGroupRankingSection();
    });

    const topNInput = document.getElementById('topNInput');
    topNInput?.addEventListener('input', (e) => {
      const raw = e.target.value.trim();
      const v = raw === '' ? 0 : parseInt(raw, 10);
      if (!isNaN(v) && v >= 0) {
        state.topN = v;
        if (v > 0 && state.studentStatusFilter === 'ABSENT') {
          state.studentStatusFilter = 'ALL';
          const statusSel = document.getElementById('studentStatusFilter');
          if (statusSel) statusSel.value = 'ALL';
        }
        document.querySelectorAll('.quick-top-btn').forEach((b) => {
          b.classList.toggle('active', parseInt(b.getAttribute('data-top'), 10) === v);
        });
        renderTopStudentsSection();
      }
    });

    document.querySelectorAll('.quick-top-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.quick-top-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        const val = parseInt(btn.getAttribute('data-top'), 10) || 0;
        state.topN = val;
        if (topNInput) topNInput.value = val > 0 ? String(val) : '';
        if (val > 0 && state.studentStatusFilter === 'ABSENT') {
          state.studentStatusFilter = 'ALL';
          const statusSel = document.getElementById('studentStatusFilter');
          if (statusSel) statusSel.value = 'ALL';
        }
        renderTopStudentsSection();
      });
    });

    document.getElementById('includeTiesCheckbox')?.addEventListener('change', (e) => {
      state.includeTies = e.target.checked;
      renderTopStudentsSection();
    });

    document.getElementById('showAllSubjectsTopCheckbox')?.addEventListener('change', (e) => {
      state.showAllSubjectsTop = e.target.checked;
      renderTopStudentsSection();
    });

    document.getElementById('studentSearchInput')?.addEventListener('input', (e) => {
      state.studentSearchQuery = e.target.value;
      renderTopStudentsSection();
    });
    document.getElementById('studentStatusFilter')?.addEventListener('change', (e) => {
      state.studentStatusFilter = e.target.value;
      if (state.studentStatusFilter === 'ABSENT' && state.topN > 0) {
        state.topN = 0;
        if (topNInput) topNInput.value = '';
        document.querySelectorAll('.quick-top-btn').forEach((b) => {
          b.classList.toggle('active', parseInt(b.getAttribute('data-top'), 10) === 0);
        });
      }
      renderTopStudentsSection();
    });

    document.getElementById('btnReplayAnimation')?.addEventListener('click', () => refreshAllUI(true));
    document.getElementById('btnExportCurrentPhoDiem')?.addEventListener('click', () => {
      exportHighResPhoDiemCard(getCurrentSession(), state.currentSubject, state.filterTeacher, state.filterGrade);
    });
    document.getElementById('btnExportMultiSession')?.addEventListener('click', exportMultiSessionImage);
    document.getElementById('btnExportGroupRanking')?.addEventListener('click', exportGroupRankingImage);
    document.getElementById('btnExportTopStudentsImg')?.addEventListener('click', exportTopStudentsImage);
    document.getElementById('btnExportTopCSV')?.addEventListener('click', exportTopStudentsCSV);
    document.getElementById('btnBatchExportAll')?.addEventListener('click', batchExportAllSubjects);
    document.getElementById('btnBatchExportFromGrid')?.addEventListener('click', batchExportAllSubjects);

    window.addEventListener('scroll', syncStickyReportActionBars, { passive: true });
    window.addEventListener('resize', () => {
      syncSidebarToggleLabel();
      refreshAllUI(false);
    });
    setupMainChartInteractivity();
    setupStatTableLatexTooltips();
  }

  document.addEventListener('DOMContentLoaded', () => {
    loadInitialData();
    initAuthenticationSystem();
    bindEvents();
    updateViewModeVisibility();
    refreshAllUI(true);
  });
})();
