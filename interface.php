<?php

defined('ABSPATH') || exit;

if (!class_exists('WP_List_Table')) {
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class Login_Activity_Table extends WP_List_Table {

    private readonly string $activity_table;
    private string $date_format;
    private string $time_format;
    private ?array $counts = null;
    private array $filters = [];

    public function __construct() {
        global $wpdb;

        $this->activity_table = $wpdb->prefix . 'login_activity';
        $this->date_format = (string)get_option('date_format', 'Y-m-d');
        $this->time_format = (string)get_option('time_format', 'H:i');

        foreach (['s', 'date', 'status', 'order'] as $key) {
            $value = $_GET[$key] ?? '';
            $this->filters[$key] = is_string($value) ? sanitize_text_field(wp_unslash($value)) : '';
        }
        $this->filters['s'] = mb_substr($this->filters['s'], 0, 100);

        parent::__construct([
            'singular' => 'loginactivity',
            'plural' => 'loginactivity'
        ]);
    }

    /**
     * Retrieve login logs data from the database.
     */
    private function get_login_activity(int $per_page, int $page_number): array {
        global $wpdb;

        $where_clause = $this->build_where_clause();
        $order = strtoupper($this->filters['order']) === 'ASC' ? 'ASC' : 'DESC';

        $sql = "
            SELECT
                id,
                login,
                ip,
                status,
                log_date
            FROM {$this->activity_table}
            {$where_clause}
            ORDER BY log_date $order, id {$order}
        ";

        $sql .= $wpdb->prepare(" LIMIT %d OFFSET %d", $per_page, ($page_number - 1) * $per_page);

        return (array)$wpdb->get_results($sql, ARRAY_A);
    }

    private function build_where_clause(): string {
        $where = $this->search_date_where();

        if ($this->filters['status'] === 'success') {
            $where[] = 'status = 1';
        }
        elseif ($this->filters['status'] === 'error') {
            $where[] = 'status = 0';
        }

        return $where ? ' WHERE ' . implode(' AND ', $where) : '';
    }

    private function search_date_where(): array {
        global $wpdb;

        $where = [];

        if ($this->filters['s'] !== '') {
            $like = '%' . $wpdb->esc_like($this->filters['s']) . '%';
            $where[] = $wpdb->prepare('login LIKE %s', $like);
        }

        if (str_contains($this->filters['date'], '-')) {
            [$year, $month] = array_map('intval', explode('-', $this->filters['date'], 2));

            if ($year > 0 && $year < 9999 && $month > 0 && $month <= 12) {
                $start = sprintf('%04d-%02d-01 00:00:00', $year, $month);
                $end = $month === 12 ? sprintf('%04d-01-01 00:00:00', $year + 1) : sprintf('%04d-%02d-01 00:00:00', $year, $month + 1);
                $where[] = $wpdb->prepare('log_date >= %s AND log_date < %s', get_gmt_from_date($start), get_gmt_from_date($end));
            }
        }

        return $where;
    }

    protected function record_count(): int {
        $counts = $this->get_counts();
        $status = $this->filters['status'];

        return (int)match ($status) {
            'success' => $counts['successes'] ?? 0,
            'error' => $counts['errors'] ?? 0,
            default => $counts['total'] ?? 0,
        };
    }

    public function no_items(): void {
        esc_html_e('No logs available.', 'wp-login-activity');
    }

    private function get_counts(): array {
        if ($this->counts !== null) {
            return $this->counts;
        }

        global $wpdb;

        $where = $this->search_date_where();
        $where_clause = $where ? ' WHERE ' . implode(' AND ', $where) : '';

        $sql = "
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) AS successes,
                SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) AS errors
            FROM {$this->activity_table}
            {$where_clause}
        ";

        return $this->counts = (array)$wpdb->get_row($sql, ARRAY_A);
    }

    protected function get_views(): array {
        $counts = $this->get_counts();
        $all_url = remove_query_arg(['s', 'paged', 'status', 'date']);
        $base_args = add_query_arg([
            's' => $this->filters['s'] !== '' ? rawurlencode($this->filters['s']) : false,
            'date' => $this->filters['date'] !== '' ? rawurlencode($this->filters['date']) : false,
        ], $all_url);

        $all_class = !in_array($this->filters['status'], ['success', 'error'], true) ? ' class="current"' : '';
        $success_class = $this->filters['status'] === 'success' ? ' class="current"' : '';
        $error_class = $this->filters['status'] === 'error' ? ' class="current"' : '';

        return [
            'all' => sprintf(
                '<a href="%s"%s>%s <span class="count">(%d)</span></a>',
                esc_url($base_args),
                $all_class,
                esc_html__('All', 'wp-login-activity'),
                (int)($counts['total'] ?? 0)
            ),
            'successful_attempts' => sprintf(
                '<a href="%s"%s>%s <span class="count">(%d)</span></a>',
                esc_url(add_query_arg(['status' => 'success'], $base_args)),
                $success_class,
                esc_html__('Successful attempts', 'wp-login-activity'),
                (int)($counts['successes'] ?? 0)
            ),
            'failed_attempts' => sprintf(
                '<a href="%s"%s>%s <span class="count">(%d)</span></a>',
                esc_url(add_query_arg(['status' => 'error'], $base_args)),
                $error_class,
                esc_html__('Failed attempts', 'wp-login-activity'),
                (int)($counts['errors'] ?? 0)
            ),
        ];
    }

    public function get_columns(): array {
        return [
            'login' => esc_html__('Login', 'wp-login-activity'),
            'ip' => esc_html__('IP', 'wp-login-activity'),
            'status' => esc_html__('Status', 'wp-login-activity'),
            'log_date' => esc_html__('Log date', 'wp-login-activity'),
        ];
    }

    public function column_default($item, $column_name) {
        switch ($column_name) {
            case 'login':
            case 'ip':
                return !empty($item[$column_name]) ? esc_html($item[$column_name]) : '-';

            case 'status':
                $is_success = (int)$item['status'] === 1;

                return $is_success
                    ? '<span style="color:#5b841b">' . esc_html__('Success', 'wp-login-activity') . '</span>'
                    : '<span style="color:#f00">' . esc_html__('Error', 'wp-login-activity') . '</span>';

            case 'log_date':
                return esc_html(wp_date($this->date_format . ', ' . $this->time_format, strtotime($item['log_date'] . ' UTC')));

            default:
                return '';
        }
    }

    public function get_sortable_columns(): array {
        return [
            'log_date' => ['log_date', false]
        ];
    }

    /**
     * Handles data query, filtering, sorting, and pagination.
     */
    public function prepare_items(): void {
        $this->_column_headers = $this->get_column_info();

        $per_page = min($this->get_items_per_page('login_logs_per_page', 100), 999);
        $total_items = $this->record_count();

        $this->set_pagination_args([
            'total_items' => $total_items,
            'per_page' => $per_page
        ]);

        $this->items = $total_items ? $this->get_login_activity($per_page, $this->get_pagenum()) : [];
    }

    private function display_date_dropdown(): void {
        global $wpdb, $wp_locale;

        $dates = [];
        $latest = $wpdb->get_var("SELECT log_date FROM $this->activity_table ORDER BY log_date DESC LIMIT 1");

        // Seek once per populated local month using the date index, without scanning every log.
        while ($latest !== null) {
            $month = get_date_from_gmt($latest, 'Y-m');
            $dates[] = $month;
            $start = get_gmt_from_date($month . '-01 00:00:00');
            $latest = $wpdb->get_var($wpdb->prepare(
                "SELECT log_date FROM $this->activity_table WHERE log_date < %s ORDER BY log_date DESC LIMIT 1",
                $start
            ));
        }

        $selected_date = $this->filters['date'];

        ?>

        <label for="filter-by-date" class="screen-reader-text"><?php esc_html_e('Filter by date', 'wp-login-activity'); ?></label>
        <select name="date" id="filter-by-date">
            <option value=""><?php esc_html_e('All dates', 'wp-login-activity') ?></option>

            <?php

            foreach ($dates as $date) {
                [$year, $month] = explode('-', $date);

                printf(
                    "<option %s value='%s'>%s</option>\n",
                    selected($selected_date, $date, false),
                    esc_attr($date),
                    sprintf(
                        /* translators: 1: month name, 2: four-digit year */
                        esc_html__('%1$s %2$s', 'wp-login-activity'),
                        esc_html($wp_locale->get_month($month)),
                        esc_html($year)
                    )
                );
            }

            ?>
        </select>

        <?php
    }

    protected function extra_tablenav($which): void {
        if ($which !== 'top') {
            return;
        }

        ?>

        <div class="alignleft actions">
            <?php

            $this->display_date_dropdown();
            submit_button(esc_html__('Filter', 'wp-login-activity'), '', 'filter_action', false, ['id' => 'post-query-submit']);

            ?>
        </div>

        <?php
    }
}

class Login_Activity_Table_Screen {

    public $logs_obj;

    public function __construct() {
        add_filter('set-screen-option', [__CLASS__, 'set_screen'], 10, 3);
        add_action('admin_menu', [$this, 'add_logs_submenu_page']);
    }

    public static function set_screen($status, $option, $value) {
        if ($option !== 'login_logs_per_page') {
            return $status;
        }

        return absint($value);
    }

    public function add_logs_submenu_page(): void {
        $hook = add_submenu_page(
            'tools.php',
            esc_html__('Login activity', 'wp-login-activity'),
            esc_html__('Login activity', 'wp-login-activity'),
            'manage_options',
            'login-activity',
            [$this, 'render_login_activity_table']
        );

        add_action("load-$hook", [$this, 'screen_option']);
    }

    public function render_login_activity_table(): void {
        ?>

        <div class="wrap">
            <h1 class="wp-heading-inline"><?php esc_html_e('Login logs', 'wp-login-activity') ?></h1>
            <hr class="wp-header-end">
            <?php $this->logs_obj->views() ?>
            <form method="get">
                <input type="hidden" name="page" value="login-activity"/>
                <input type="hidden" name="status" value="<?php echo esc_attr(sanitize_key(wp_unslash($_GET['status'] ?? ''))) ?>"/>
                <?php
                $this->logs_obj->prepare_items();
                $this->logs_obj->search_box(esc_html__('Search login', 'wp-login-activity'), 'login-log');
                $this->logs_obj->display();
                ?>
            </form>
        </div>

        <?php
    }

    public function screen_option(): void {
        $option = 'per_page';
        $args = [
            'label' => esc_html__('Logs per page', 'wp-login-activity'),
            'default' => 100,
            'option' => 'login_logs_per_page'
        ];

        add_screen_option($option, $args);

        $this->logs_obj = new Login_Activity_Table();
    }

}

new Login_Activity_Table_Screen();
