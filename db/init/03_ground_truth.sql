-- 실험 정답지 (탐지 엔진은 이 테이블을 보면 안 됨, 평가용)
CREATE TABLE ground_truth_apis (
  service       VARCHAR(50) PRIMARY KEY,
  path_prefix   VARCHAR(100) NOT NULL,
  is_vulnerable BOOLEAN NOT NULL
);
INSERT INTO ground_truth_apis VALUES
  ('members',  '/members',  true),
  ('orders',   '/orders',   true),
  ('profiles', '/profiles', false),
  ('payments', '/payments', false);