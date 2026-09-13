/**
 * controller package
 *
 * Contains REST controllers that handle incoming HTTP requests:
 *   - AuthController.java       POST /api/auth/register, POST /api/auth/login
 *   - UserController.java       GET  /api/users, GET /api/users/{id}, GET /api/users/me
 *   - MessageController.java    POST /api/messages/send, GET /api/messages/received,
 *                               GET  /api/messages/sent, GET /api/messages/{id}/decrypt
 *   - AdminController.java      GET  /api/admin/users, PUT /api/admin/users/{id}/toggle,
 *                               GET  /api/admin/messages, GET /api/admin/stats
 *
 * Controllers delegate all business logic to the service layer.
 * These classes will be implemented in Phase 3 and beyond.
 */
package com.securemsg.controller;
