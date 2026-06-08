/*
 * Internal source backup – do not distribute.
 *
 * SQL Injection vulnerability – CWE-89
 *
 * Dataflow:
 *
 *   [HTTP layer]          UserController.login(request)
 *                               │
 *                         username, password read from
 *                         HttpServletRequest parameters  ← TAINTED SOURCE
 *                               │
 *   [Service layer]       UserService.authenticate(username, password)
 *                               │
 *                         values forwarded unchanged     ← PROPAGATION
 *                               │
 *   [Repository layer]    UserRepository.findByCredentials(username, password)
 *                               │
 *                         string concatenated into SQL   ← SINK (injection)
 *                               │
 *   [Persistence layer]   FakeDatabase.execute(sql)
 *                               │
 *                         query parsed & rows returned   ← EFFECT
 */

import java.util.*;

// ── Fake in-memory database ───────────────────────────────────────────────

class FakeDatabase {

    // Simulated rows: each row is a map of column → value.
    private static final List<Map<String, String>> USERS = new ArrayList<>();

    static {
        Map<String, String> admin = new HashMap<>();
        admin.put("id",       "1");
        admin.put("username", "admin");
        admin.put("password", "admin123");
        admin.put("role",     "admin");
        USERS.add(admin);

        Map<String, String> jim = new HashMap<>();
        jim.put("id",       "2");
        jim.put("username", "jim");
        jim.put("password", "ncc-1701");
        jim.put("role",     "user");
        USERS.add(jim);
    }

    /**
     * Toy SQL engine: understands
     *   SELECT * FROM users WHERE username='X' AND password='Y'
     *
     * Parses the raw WHERE clause via string operations so that injected
     * tokens such as {@code ' OR '1'='1} and {@code --} take effect exactly
     * as they would against a real JDBC driver.
     */
    List<Map<String, String>> execute(String sql) {
        System.out.println("[DB] Executing: " + sql);

        int whereIdx = sql.toUpperCase().indexOf("WHERE");
        if (whereIdx == -1) return Collections.emptyList();

        String whereClause = sql.substring(whereIdx + 5).trim();

        // Injection bypass 1: always-true OR clause
        if (alwaysTrue(whereClause)) {
            System.out.println("[DB] WHERE is universally true – returning all rows");
            return new ArrayList<>(USERS);
        }

        // Injection bypass 2: trailing -- comment drops the password check
        if (whereClause.contains("--")) {
            whereClause = whereClause.substring(0, whereClause.indexOf("--")).trim();
            System.out.println("[DB] Comment stripped – evaluating: " + whereClause);
        }

        List<Map<String, String>> results = new ArrayList<>();
        for (Map<String, String> row : USERS) {
            if (rowMatchesWhere(row, whereClause)) {
                results.add(row);
            }
        }
        return results;
    }

    private boolean alwaysTrue(String clause) {
        String upper = clause.toUpperCase();
        return upper.contains("OR 1=1")
            || upper.contains("OR '1'='1'")
            || upper.matches(".*OR\\s+\\d+=\\d+.*");
    }

    private boolean rowMatchesWhere(Map<String, String> row, String clause) {
        String[] conditions = clause.split("(?i)\\s+AND\\s+");
        for (String cond : conditions) {
            String[] parts = cond.split("=", 2);
            if (parts.length != 2) return false;
            String col = parts[0].trim().toLowerCase();
            String val = parts[1].trim().replaceAll("^'|'$", "");
            if (!val.equals(row.getOrDefault(col, ""))) return false;
        }
        return true;
    }
}

// ── Repository layer (SQL injection sink) ────────────────────────────────

public class UserRepository {

    private final FakeDatabase db;

    public UserRepository(FakeDatabase db) {
        this.db = db;
    }

    /**
     * VULNERABLE – {@code username} and {@code password} arrive tainted from
     * the HTTP layer and are concatenated directly into the SQL string with no
     * parameterisation or escaping.
     *
     * <p>Safe alternative (JDBC):
     * <pre>
     *   PreparedStatement ps = conn.prepareStatement(
     *       "SELECT * FROM users WHERE username = ? AND password = ?");
     *   ps.setString(1, username);
     *   ps.setString(2, password);
     * </pre>
     */
    public List<Map<String, String>> findByCredentials(String username, String password) {
        // ── SINK ─────────────────────────────────────────────────────────
        // Both parameters are tainted from the HTTP request and embedded
        // verbatim.  The attacker controls everything after WHERE.
        String sql = "SELECT * FROM users"
                   + " WHERE username='" + username
                   + "' AND password='" + password + "'";
        return db.execute(sql);
    }

    // ── Service layer (propagation) ───────────────────────────────────────

    static class UserService {

        private final UserRepository repo;

        UserService(UserRepository repo) {
            this.repo = repo;
        }

        /**
         * Business-logic wrapper.  Forwards tainted values unchanged –
         * no validation or sanitisation is applied here.
         */
        Optional<Map<String, String>> authenticate(String username, String password) {
            List<Map<String, String>> rows = repo.findByCredentials(username, password);
            return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
        }
    }

    // ── HTTP controller (tainted source) ─────────────────────────────────

    static class UserController {

        private final UserService service;

        UserController(UserService service) {
            this.service = service;
        }

        /**
         * Simulates a {@code POST /login} handler.
         *
         * <p>In a real Spring/Jakarta-EE app the parameters would come from
         * {@code @RequestParam} or {@code HttpServletRequest.getParameter()}.
         * A plain {@link Map} is used here to keep the demo self-contained.
         *
         * <p>── TAINTED SOURCE ─────────────────────────────────────────────
         * {@code request.get("username")} and {@code request.get("password")}
         * are attacker-controlled strings.  No validation is applied before
         * they enter the call chain.
         */
        String login(Map<String, String> request) {
            String username = request.get("username"); // ← tainted
            String password = request.get("password"); // ← tainted

            Optional<Map<String, String>> user = service.authenticate(username, password);

            if (user.isPresent()) {
                return "LOGIN OK – welcome, " + user.get().get("username")
                     + " (role=" + user.get().get("role") + ")";
            }
            return "LOGIN FAILED";
        }
    }

    // ── Entry point / PoC ─────────────────────────────────────────────────

    public static void main(String[] args) {

        FakeDatabase   db         = new FakeDatabase();
        UserRepository repo       = new UserRepository(db);
        UserService    service    = new UserService(repo);
        UserController controller = new UserController(service);

        System.out.println("=== SQL Injection dataflow demo (CWE-89) ===\n");

        // ── Case 1: Legitimate login ──────────────────────────────────
        System.out.println("-- Case 1: valid credentials --");
        Map<String, String> req1 = new HashMap<>();
        req1.put("username", "jim");
        req1.put("password", "ncc-1701");
        System.out.println(controller.login(req1));
        System.out.println();

        // ── Case 2: Wrong password (no injection) ─────────────────────
        System.out.println("-- Case 2: wrong password --");
        Map<String, String> req2 = new HashMap<>();
        req2.put("username", "jim");
        req2.put("password", "wrong");
        System.out.println(controller.login(req2));
        System.out.println();

        // ── Case 3: Classic ' OR '1'='1 authentication bypass ─────────
        // Resulting SQL:
        //   SELECT * FROM users WHERE username='' OR '1'='1'
        //   AND password='anything'
        // The OR clause makes the WHERE universally true.
        System.out.println("-- Case 3: ' OR '1'='1 bypass --");
        Map<String, String> req3 = new HashMap<>();
        req3.put("username", "' OR '1'='1");
        req3.put("password", "anything");
        System.out.println(controller.login(req3));
        System.out.println();

        // ── Case 4: Comment-out password check ────────────────────────
        // Resulting SQL:
        //   SELECT * FROM users WHERE username='admin'--' AND password='x'
        //   Everything after -- is a comment; only the username is checked.
        System.out.println("-- Case 4: admin'-- comment injection --");
        Map<String, String> req4 = new HashMap<>();
        req4.put("username", "admin'--");
        req4.put("password", "doesnotmatter");
        System.out.println(controller.login(req4));
        System.out.println();
    }
}
