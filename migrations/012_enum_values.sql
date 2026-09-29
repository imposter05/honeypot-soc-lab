-- Hiten | 2026
-- 012_enum_values.sql
-- New enum values. ALTER TYPE ... ADD VALUE cannot be used inside the
-- transaction that adds it, so this migration runs without one.
-- PostgreSQL cannot drop enum values, so Down is a no-op.

-- +goose NO TRANSACTION
-- +goose Up
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'connection.denied';
ALTER TYPE ioc_type ADD VALUE IF NOT EXISTS 'ssh-client';

-- +goose Down
SELECT 1;
