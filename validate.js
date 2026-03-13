// middleware/validate.js — Input validation rules

const { body, param, query, validationResult } = require('express-validator');

// ── Handler: kembalikan error validasi ───────────────────────────────────────
const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages = errors.array().map(e => e.msg);
    return res.status(422).json({ success: false, message: messages[0], errors: messages });
  }
  next();
};

// ── Rules: Auth ───────────────────────────────────────────────────────────────
const registerRules = [
  body('name')
    .trim().isLength({ min: 2, max: 80 }).withMessage('Nama harus 2-80 karakter.')
    .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/).withMessage('Nama hanya boleh huruf, spasi, tanda kutip, dan tanda hubung.'),

  body('email')
    .trim().isEmail().withMessage('Format email tidak valid.')
    .normalizeEmail().isLength({ max: 254 }).withMessage('Email terlalu panjang.'),

  body('password')
    .isLength({ min: 8, max: 128 }).withMessage('Password harus 8-128 karakter.')
    .matches(/[A-Z]/).withMessage('Password harus mengandung minimal 1 huruf kapital.')
    .matches(/[a-z]/).withMessage('Password harus mengandung minimal 1 huruf kecil.')
    .matches(/[0-9]/).withMessage('Password harus mengandung minimal 1 angka.')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/).withMessage('Password harus mengandung minimal 1 karakter khusus (!@#$%^&*).'),

  handleValidation
];

const loginRules = [
  body('email')
    .trim().isEmail().withMessage('Format email tidak valid.')
    .normalizeEmail().isLength({ max: 254 }),

  body('password')
    .notEmpty().withMessage('Password wajib diisi.')
    .isLength({ max: 128 }).withMessage('Password terlalu panjang.'),

  handleValidation
];

const changePasswordRules = [
  body('currentPassword').notEmpty().withMessage('Password lama wajib diisi.'),
  body('newPassword')
    .isLength({ min: 8, max: 128 }).withMessage('Password baru harus 8-128 karakter.')
    .matches(/[A-Z]/).withMessage('Harus ada huruf kapital.')
    .matches(/[a-z]/).withMessage('Harus ada huruf kecil.')
    .matches(/[0-9]/).withMessage('Harus ada angka.')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/).withMessage('Harus ada karakter khusus.'),
  handleValidation
];

// ── Rules: User ───────────────────────────────────────────────────────────────
const updateProfileRules = [
  body('name')
    .trim().isLength({ min: 2, max: 80 }).withMessage('Nama harus 2-80 karakter.')
    .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/).withMessage('Nama mengandung karakter tidak valid.'),
  handleValidation
];

const createJobRules = [
  body('scale_mode').isIn(['2x','4x','8x']).withMessage('Mode upscale tidak valid.'),
  body('content_type').isIn(['photo','portrait','anime','landscape']).withMessage('Tipe konten tidak valid.'),
  body('noise_level').isInt({ min: 0, max: 100 }).withMessage('Level noise harus 0-100.'),
  body('sharpness').isInt({ min: 0, max: 100 }).withMessage('Sharpness harus 0-100.'),
  handleValidation
];

const createApiKeyRules = [
  body('name')
    .trim().isLength({ min: 2, max: 60 }).withMessage('Nama key harus 2-60 karakter.')
    .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Nama key mengandung karakter tidak valid.'),
  handleValidation
];

// ── Rules: Admin ──────────────────────────────────────────────────────────────
const createUserAdminRules = [
  body('name').trim().isLength({ min: 2, max: 80 }).withMessage('Nama harus 2-80 karakter.'),
  body('email').trim().isEmail().withMessage('Email tidak valid.').normalizeEmail(),
  body('password').isLength({ min: 8, max: 128 }).withMessage('Password minimal 8 karakter.'),
  body('role').isIn(['user','admin']).withMessage('Role tidak valid.'),
  body('plan').isIn(['free','pro','ultra']).withMessage('Paket tidak valid.'),
  handleValidation
];

const updateUserAdminRules = [
  body('status').optional().isIn(['active','suspended','banned']).withMessage('Status tidak valid.'),
  body('plan').optional().isIn(['free','pro','ultra']).withMessage('Paket tidak valid.'),
  body('role').optional().isIn(['user','admin','superadmin']).withMessage('Role tidak valid.'),
  body('credits').optional().isInt({ min: 0, max: 999999 }).withMessage('Kredit tidak valid.'),
  handleValidation
];

const uuidParamRules = [
  param('id').isUUID().withMessage('ID tidak valid.'),
  handleValidation
];

const paginationRules = [
  query('page').optional().isInt({ min: 1, max: 1000 }).withMessage('Page tidak valid.').toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit tidak valid.').toInt(),
  handleValidation
];

module.exports = {
  registerRules, loginRules, changePasswordRules, updateProfileRules,
  createJobRules, createApiKeyRules,
  createUserAdminRules, updateUserAdminRules, uuidParamRules, paginationRules
};
