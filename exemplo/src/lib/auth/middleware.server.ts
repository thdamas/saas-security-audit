import { createMiddleware } from '@tanstack/react-start'

export const requireUser = createMiddleware().server(async ({ next, context }) => {
  if (!context.user) throw new Error('unauthorized')
  return next()
})

export const requireStaff = createMiddleware().server(async ({ next, context }) => {
  if (context.user?.role !== 'staff') throw new Error('forbidden')
  return next()
})
