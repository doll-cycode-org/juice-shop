// DEMO FINDING (SAST / medium): taint flows through local variables and string building
// before reaching the sink, all within one function.
import { type Request, type Response } from 'express'
import { exec } from 'child_process'
import { Sequelize } from 'sequelize'
import jwt from 'jsonwebtoken'
import fs from 'fs'

const sequelize = new Sequelize('sqlite::memory:')

// CWE-89: SQL injection via template literal built over several lines
export async function searchOrders (req: Request, res: Response) {
  const status = req.body.status
  const sortColumn = req.query.sort ?? 'createdAt'
  let query = 'SELECT * FROM Orders WHERE 1=1'
  if (status) {
    query += ` AND status = '${status}'`
  }
  query += ` ORDER BY ${sortColumn}`
  const [rows] = await sequelize.query(query)
  res.json(rows)
}

// CWE-78: OS command injection, filename flows into a shell string
export function exportInvoice (req: Request, res: Response) {
  const orderId = req.params.id
  const format = req.query.format || 'pdf'
  const cmd = `wkhtmltopdf /tmp/invoice-${orderId}.html /tmp/out.${format}`
  exec(cmd, (err, stdout) => {
    if (err) return res.status(500).send(err.message)
    res.send(stdout)
  })
}

// CWE-347: JWT verification accepts the "none" algorithm
export function whoAmI (req: Request, res: Response) {
  const token = (req.headers.authorization ?? '').replace('Bearer ', '')
  const payload = jwt.verify(token, 'secret', { algorithms: ['HS256', 'none'] as any })
  res.json(payload)
}

// CWE-601: open redirect
export function continueCheckout (req: Request, res: Response) {
  const next = req.query.returnUrl as string
  res.redirect(next)
}

// CWE-1333: ReDoS, catastrophic backtracking on user input
export function validateCoupon (req: Request, res: Response) {
  const couponPattern = /^([a-zA-Z0-9]+)*$/
  res.json({ valid: couponPattern.test(req.body.coupon) })
}

// CWE-22: path traversal with a naive, bypassable filter
export function downloadReceipt (req: Request, res: Response) {
  const file = (req.query.file as string).replace('../', '')
  res.send(fs.readFileSync('/var/receipts/' + file))
}
