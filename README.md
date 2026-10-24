# secnews: 보안 뉴스 → 텔레그램

뉴스를 모아 Gemini로 걸러내고 한국어로 번역해서, 매시 정각에 승인된 구독자들에게 텔레그램으로 보냅니다.
GitHub Actions(공개 레포는 무료)에서 돌고, 서버나 유료 서비스가 필요 없습니다. Python 표준 라이브러리에 암호화용 `cryptography` 하나만 씁니다(버전·해시 고정, `requirements.txt`).

## 받는 메시지

설정해 둔 주제에 맞는 보안 뉴스를 골라 칸별로 묶어서 받습니다.
기사마다 제목(원문 링크), 요약, 출처, 시간이 붙고, 영어 기사는 한국어로 번역됩니다.
바로 알아야 할 중요한 기사에는 🚨가 붙습니다.

## 동작 방식

| 주기 | 하는 일 |
|---|---|
| 5분마다 | 구독 신청·해지와 승인 버튼 처리, 🚨 긴급 보안 속보 확인 |
| 매시 정각 첫 실행 (07~21시) | 뉴스 수집 → 걸러내기 → 번역 → 발송 |
| 22시~05시 | 정기 발송 쉼 (`quiet_hours`) |
| 06시 | 밤사이 기사 모음 (칸별 상한 1.5배, `morning_cap_factor`) |

`"night_notice": true`이면 22시 첫 실행 때 모두에게 알림 소리 없이 "취침 모드(05시까지 정기 발송 쉼, 06시에 모아서 발송)" 안내를 한 번 보냅니다.

**🚨 긴급 보안 속보**: 5분마다 빠른 출처(`"instant": true`)만 확인해서, 최근 3시간 안의 새 기사 중
긴급 키워드(`keywords.instant`)에 걸리는 것을 후보로 잡고, Gemini가 긴급하다고 확인하면
정각을 기다리지 않고 바로 보냅니다(한 번에 최대 5건). 밤(22~06시)에는 알림 소리 없이 보냅니다.
바로 보낸 기사는 정기 발송에서 다시 보내지 않고, 긴급이 아닌 후보는 다음 정기 발송을 기다립니다.

5분 실행은 cron-job.org가 GitHub API로 워크플로를 호출합니다(`scheduled=true`). GitHub 자체 스케줄은 자주 밀려서 예비용입니다.

출처는 최대 6개를 동시에 조회하며, 같은 호스트는 최대 2개만 조회합니다. 결과는 설정 순서대로
처리하므로 먼저 등록한 출처의 중복 기사 우선순위는 유지됩니다. `feed_workers: 1`이면 순차 조회합니다.
원문 발행시각 조회는 별도의 공통 시간 예산과 캐시를 사용합니다.

외부 콘텐츠는 HTTP/HTTPS의 기본 포트만 허용하고, 내부/예약 주소와 사용자정보가 담긴 URL을
거부합니다. DNS로 확인한 공인 주소에 직접 연결하고 HTTPS 인증서·원래 호스트 이름 검증을 유지합니다.
리디렉션마다 주소를 다시 검사하며 HTTPS에서 HTTP로 내려가는 이동도 거부합니다.
이 연결 방식을 보장할 수 없는 설정된 프록시는 우회하지 않고 콘텐츠 조회를 거부합니다.
운영 GitHub 러너는 별도 프록시 없는 환경을 사용하며, 클라우드 개발 환경의 프록시에서는
모의 테스트 또는 읽기 전용 GitHub 진단을 사용합니다.
피드는 기본 최대 8MiB(`max_bytes`로 더 낮게 설정 가능), 출처당 최대 5,000항목을 처리합니다.
응답 읽기·리디렉션은 하나의 시간 예산을 사용하며 DNS 자체의 시간 제한은 OS 설정을 따릅니다.
원문 소개/날짜는 필요한 앞부분만 읽습니다. 긴 제목은 AI 추가 요청 없이 표시 길이를 제한합니다.

**걸러내기**
1. 키워드 점수(`keywords`): 보안 단어가 없거나 점수가 낮은 기사, 48시간보다 오래된 기사, 이미 보낸 기사를 뺍니다.
2. Gemini 판단: 보안과 무관한 기사, 같은 사건의 다른 언어·다른 매체 기사, 지난 48시간 안에 보낸 사건을 빼고, 칸·분류·긴급도를 정하고 번역까지 합니다. 한 번 발송에 요청 1번입니다.
3. 칸마다, 출처마다 보낼 건수에 상한이 있습니다.

**Gemini 무료 한도**: 무료 등급은 모델마다 하루 요청 수가 따로 정해져 있습니다(Flash 20, Flash Lite 500, 2026년 10월 기준).
`gemini-flash-latest` → `gemini-2.5-flash` → `gemini-3.6-flash` → `gemini-3-flash-preview`는 각각 18번,
이후 `gemini-flash-lite-latest` → `gemini-3.1-flash-lite`는 각각 450번까지 씁니다(설정으로 변경 가능).
일일 한도 초과(429)나 없는 모델(404)이 오면 그날은 다음 모델로 넘어갑니다.
일시적인 분당 제한은 1분, 서버 오류·시간초과는 15분 쉬고 그동안 다른 모델을 사용합니다.
모두 휴식 중이면 추가 요청 없이 보류합니다. 분류 요청과 모델 전환은 전체 7분 예산을 공유하며,
분류의 개별 요청은 Flash 최대 45초, Lite 최대 90초와 남은 예산 중 짧은 값을 사용합니다.
Lite 생각하기 설정은 유지합니다(네트워크 소켓 제한이므로 엄격한 실행시간 보장은 아님).
AI가 실패하면 정기 발송은 5분 뒤 한 번 더 시도하고, 계속 실패하면 다음 회차로 보류합니다.
키워드 판단만으로 일반 기사를 보내지는 않습니다.
결제 계정을 연결하지 않은 무료 등급이면 요금이 나가지 않습니다. 사용 횟수는 `gemini_usage.json`에 기록됩니다.
관리자 테스트의 API 요청도 비공개 설정 저장소의 `api-usage/`에 실행별로 기록하고,
다음 실행에서 중복 없이 합산합니다. 테스트의 발송 기록·구독자 목록은 운영 상태에 저장하지 않습니다.
표시되는 횟수는 봇의 요청 시도 기록이며, 다른 앱의 사용이나 과거 미기록 테스트까지 포함하는
Google 프로젝트 전체 사용량과는 다를 수 있습니다.

## 구독 (관리자 승인제)
- 봇에서 **/start** → 신청자에게 "접수됐어요" 안내, 관리자에게 이름과 ✅ 승인 / ❌ 거절 버튼
- 버튼은 다음 5분 실행 때 처리되고, 그 메시지가 "✅ 승인 완료 (시각)"으로 바뀝니다. 거절된 사람도 /start를 다시 누르면 새 신청으로 관리자에게 다시 옵니다.
- 관리자 본인과 예전 구독자는 승인 없이 다시 구독됩니다. **/stop**은 바로 해지됩니다.
- 관리자가 봇에 **/why 기사링크**(또는 **/why 제목 일부**)를 보내면, 최근 3일 안에 수집한 기사가 발송됐는지, 아니면 어느 단계(키워드 점수, AI 판단, 중복, 칸 상한 등)에서 빠졌는지 알려 줍니다.
- 매주 월요일 9시 이후 첫 정기 발송 때 관리자에게 주간 리포트(수집·통과·AI 제외·발송 건수, 1주일 내내 0건인 출처, AI가 뺀 기사 예시)를 보냅니다.
- 관리자가 봇에 **/stats**를 보내면 다음 5분 실행 때 구독 중·승인 대기·해지·거절 인원을 관리자에게만 알려 줍니다.
- 관리자가 봇에 **/test**를 보내면 구독 목록을 바꾸지 않고 신청→버튼→처리 과정을 미리 볼 수 있습니다.
- 승인제를 끄려면 설정 파일의 `"require_approval": false`.
- 승인제가 켜져 있으면 유효한 개인 관리자 ID가 없을 때 시작을 중단합니다.
  신청 알림은 같은 채팅당 기본 30분 간격, 회차당 최대 10명이며 대기 신청은 다음 실행에서 이어 처리합니다.
  관리자 승인/거절 뒤의 재신청은 새로 처리할 수 있습니다.

구독자 아이디와 이름은 공개 레포에 두지 않고, 봇 토큰에서 만든 키로 **AES-256-GCM** 암호화한 `subscribers.json`에 담아 Actions 캐시에 보관합니다. 구독자가 바뀔 때마다 같은 암호화 파일을 비공개 레포 `New2_config`의 `backup/`에도 저장해서, 캐시가 지워지면 다음 실행 때 거기서 복구합니다 (봇 토큰 교체 전에 기존 키로 상태를 이관해야 합니다). 로그에는 `12***90`처럼 일부만 보입니다.

공개 Actions 캐시에는 기사 URL·제목·발송 기록·AI 사용량·날짜 캐시·검토 파일을 포함한
전체 `.state`를 **AES-256-GCM으로 암호화한 파일만** 저장합니다.
캐시 전용 키는 봇 토큰에서 HKDF로 구독자 암호화와 구분해 만들고, 매번 새로운 nonce를 사용합니다.
실행할 때만 임시 러너 안에서 복호화하며, 키 불일치·변조·손상은 실행을 중단합니다.
잘못된 캐시를 빈 발송 기록으로 취급하지 않습니다. 봇 토큰을 교체하려면 기존 키로 상태를 먼저 옮겨야 합니다.
구독자 파일이나 기존 백업의 인증·형식 검증이 실패해도 빈 목록으로 덮어쓰지 않고 중단합니다.
전환 시 새 암호화 캐시가 없으면 기존 캐시를 읽어 보존하며, 새 캐시는 `secnews-encrypted-state-v1-`
이름으로 저장합니다. 과거 `secnews-state-` 평문 캐시는 전환 확인 후 별도로 삭제해야 합니다.
이 암호화는 공개 캐시 저장 내용을 보호하며, 공개 실행 로그까지 비공개로 바꾸지는 않습니다.

## 설정

Settings → Secrets and variables → Actions → **Secrets**

| 이름 | 값 |
|---|---|
| `TELEGRAM_BOT_TOKEN` | BotFather에서 받은 봇 토큰 |
| `TELEGRAM_TEST_CHAT_ID` (또는 `..._IDS`) | 관리자(본인) 텔레그램 ID: 테스트, 승인 버튼, 고장 알림을 받음 |
| `GEMINI_API_KEY` | Google AI Studio API 키 (없으면 키워드 판단 + 구글 번역) |
| `CONFIG_REPO_TOKEN` | 비공개 설정 레포 `New2_config` 토큰 (Contents: Read and write, 설정 읽기·구독자 백업·테스트 API 사용량 저장) |
| `TELEGRAM_CHAT_IDS` | (선택) 승인 없이 넣을 구독자 ID. 다음 실행 때 암호화 목록에 합쳐짐 |

cron-job.org: 5분마다 `POST https://api.github.com/repos/<owner>/<repo>/actions/workflows/secnews.yml/dispatches`,
본문 `{"ref":"claude/jolly-knuth-ufiqq1","inputs":{"scheduled":"true"}}`, 헤더에 Actions 쓰기 권한이 있는 토큰.

## 수동 실행과 테스트
- Actions → secnews → **Run workflow**: `test_me`가 기본으로 켜져 있어 **관리자에게만** 현재 뉴스를 보냅니다. 보낸 기록·구독자 목록은 바꾸지 않습니다.
- `test_me`를 끄면 모든 구독자에게 바로 보냅니다(`reset`을 켜면 보낸 기록을 지우고 다시 보냄).
- `list_chats`: 아직 처리되지 않은 봇 메시지 목록 (이름·ID 가림).
- 공개 로그에는 건수·소요시간·오류 종류만 남깁니다. 기사 제목·URL·채팅 정보·외부 응답·traceback은
  실패하거나 `verbose`를 켜도 공개하지 않습니다. 설정한 API 키·토큰은 상세 진단에서도 가립니다.
- 성공한 실행의 오류 상세는 암호화 운영 캐시의 `private-diagnostics.json`에 최근 20회·회당 최대 64KiB로
  보관합니다. `review_now` 실행 시 비공개 검토 보고서의 `diagnostics`에서 확인할 수 있습니다.
- 실패 실행·관리자 테스트·보조 도구·상세 모드의 필요한 진단은 암호화된 Actions 첨부파일로도 남깁니다
  (보관7일). `tools/state_cache.py open --archive FILE.enc --state PRIVATE_DIR`로 복호화하며,
  키는 기존 `TELEGRAM_BOT_TOKEN` 환경변수에서 읽습니다. 첨부파일에는 평문을 올리지 않습니다.
- `list_chats`의 공개 출력은 인원수만 보여주며, 세부 목록은 암호화 첨부파일에 보관합니다.
- push와 PR에는 단위 테스트만 돌고 메시지는 보내지 않습니다.
- 원문 진단의 `collection_check`는 전체 출처 수집 호환성만 점검하며 AI·메시지 전송이나 운영 상태 저장을 하지 않습니다.

## 고장 알림 (관리자에게만)
- 출처 하나가 3번 연속 실패하면 한 번 알림 (주소 변경 가능성)
- 정기 실행이 실패하면 알림 (계속 실패해도 한 시간에 한 번)
- 5분 실행이 30분 넘게 들어오지 않으면 알림 (GitHub 자체 스케줄로 매시 17분에 확인, cron-job.org가 멈췄거나 그 토큰이 만료된 경우)
- 봇 토큰 자체가 망가지면 텔레그램 알림도 못 보내므로 GitHub의 실패 메일로 확인하세요.

## 로컬에서
```bash
python3 -m unittest discover -s tests -v   # 테스트
python3 secnews.py --dry-run               # 보내지 않고 메시지만 출력 (상태 파일 안 바꿈)
```

## 설정 파일 (비공개)
- 출처·키워드·분류·발송 시간 같은 설정(`feeds.json`)은 공개 레포가 아니라 **비공개 레포 `New2_config`**에 있습니다.
  실행할 때마다 `CONFIG_REPO_TOKEN`으로 가져와서 쓰고, 공개 레포와 로그에는 남지 않습니다.
  Actions 로그에는 출처가 `source 1`처럼 번호로만 찍힙니다.
- 토큰이 만료되거나 설정 파일이 없으면 실행이 실패하고 관리자에게 알림이 갑니다.
- 단위 테스트는 `tests/test_feeds.json`(테스트에 쓰이는 단어만 담은 예시 설정)으로 돕니다.
- 피드 옵션: `security_only`(보안 키워드 있는 글만), `min_score`(출처별 최소 점수), `instant`(긴급 속보 확인 대상).
- 메시지 칸 제목, 분류 아이콘, 환영 문구, Gemini 분류 지시문도 설정 파일(`texts`, `sector_icons`, `classify_prompt`)에서 정합니다. 없으면 코드의 기본값을 씁니다.
- 보낼 뉴스가 없는 정각: `"no_news_notice"`가 `"all"`이면 모두에게 알림 소리 없이 "새로 보낼 뉴스가 없어요"를 보내고, `"admin"`이면 관리자에게만, `"off"`(기본)면 보내지 않습니다.
- Gemini 끄기: `"gemini_classify": false`(분류만 끔) 또는 `GEMINI_API_KEY` 시크릿 삭제.

## 한계
- 완전한 실시간은 아닙니다: 긴급 속보는 최대 5분, 일반 기사는 최대 1시간(밤사이 기사는 06시) 늦습니다. 승인 버튼도 최대 5분 뒤 처리됩니다.
- GitHub Actions, cron-job.org, Gemini 무료 등급, 각 피드 사이트의 정책이 바뀌면 손봐야 합니다.
- AI 판단도 100%는 아니고, 요약이 없는 기사는 제목만으로 판단합니다.
- 일부 정보(해커 조직의 주장 등)는 사실 확인 전 정보일 수 있습니다.
- 레포를 비공개로 바꾸면 Actions 무료 시간(월 2,000분)을 넘어 유료가 됩니다.
# Checking selection changes

Classification responses are validated inside model fallback: malformed fields move to the next
available model without weakening type checks. Format errors receive a brief rest and do not count
toward the two-overloaded-Flash shortcut to Lite. Model order and daily limits stay configurable.

Half-past preparation records completion separately from attempts. Incomplete preparation retries
at five-minute intervals, up to three attempts before minute 55, reusing its successful judgements.
A genuinely empty candidate set is complete and needs no retry. Preparation sends no digest or
no-news notice; ordinary digest retry rules still apply on the hour.

The **Selection quality evaluation** workflow compares a frozen private baseline with current
settings on identical labelled examples, including their saved context. It records false positives,
false negatives, precision/recall and changed examples in the private repository. Unreviewed cases
are excluded, and provider failures or differing model versions cannot count as quality gains.
This evaluates classification after keyword admission, rather than end-to-end collection accuracy.

The workflow flags regressions or tradeoffs with a failed check while preserving its private report.
It runs manually and on Mondays at 00:35 UTC. A live comparison normally uses two Lite
requests and is capped at four attempts, recorded in the existing API usage ledger; it never sends
messages or saves production news state. Budget exhaustion skips the evaluation. Disable `live`
to validate files without API calls. Private `evaluation/README.md` describes review and baseline
promotion; results never automatically change settings. Locally, run
`python3 tools/evaluate_selection.py /path/to/private-config` for offline validation.
