<?php

defined('ABSPATH') || exit;

if (!class_exists('WP_List_Table')) {
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class Login_Activity_Table extends WP_List_Table {

    private readonly string $table_name;
    private string $date_format;
    private string $time_format;

    public function __construct() {
        global $wpdb;

        $this->table_name = $wpdb->prefix . 'login_activity';
        $this->date_format = (string)get_option('date_format', 'Y-m-d');
        $this->time_format = (string)get_option('time_format', 'H:i');

        parent::__construct([
            'singular' => esc_html__('Login Activity', 'wp-login-activity'),
            'plural' => esc_html__('Login Activity', 'wp-login-activity'),
            'ajax' => false
        ]);
    }

    /**
     * Retrieve login logs data from the database.
     */
    private function get_login_activity(int $per_page = 100, int $page_number = 1): array {
        global $wpdb;

        $where_clause = $this->build_where_clause();
        $allowed_orderby = ['login', 'ip', 'status', 'log_date', 'id'];
        $orderby = !empty($_GET['orderby']) ? sanitize_key($_GET['orderby']) : 'log_date';

        if (!in_array($orderby, $allowed_orderby, true)) {
            $orderby = 'log_date';
        }

        $order = !empty($_GET['order']) ? strtoupper(wp_unslash($_GET['order'])) : 'DESC';
        $order = in_array($order, ['ASC', 'DESC'], true) ? $order : 'DESC';

        $sql = "
            SELECT
                id,
                login,
                INET6_NTOA(ip) AS ip,
                status,
                log_date
            FROM {$this->table_name}
            {$where_clause}
            ORDER BY $orderby {$order}
        ";

        if ($per_page !== -1) {
            $offset = ($page_number - 1) * $per_page;
            $sql .= $wpdb->prepare(" LIMIT %d OFFSET %d", $per_page, $offset);
        }

        return (array)$wpdb->get_results($sql, ARRAY_A);
    }

    private function build_where_clause(): string {
        global $wpdb;

        $where = [];

        if (isset($_GET['s']) && $_GET['s'] !== '') {
            $s_raw = wp_unslash($_GET['s']);
            $s_clean = mb_substr(trim(sanitize_text_field($s_raw)), 0, 100);
            $like = '%' . $wpdb->esc_like($s_clean) . '%';
            $where[] = $wpdb->prepare('login LIKE %s', $like);
        }

        if (isset($_GET['status']) && $_GET['status'] !== '') {
            $status_raw = sanitize_text_field(wp_unslash($_GET['status']));

            if ($status_raw === 'success') {
                $where[] = 'status = 1';
            }
            elseif ($status_raw === 'error') {
                $where[] = 'status = 0';
            }
        }

        if (isset($_GET['date']) && $_GET['date'] !== '') {
            $date_raw = wp_unslash($_GET['date']);
            $date_safe = sanitize_text_field($date_raw);

            if (str_contains($date_safe, '-')) {
                [$year, $month] = array_map('intval', explode('-', $date_safe, 2));

                if ($year > 0 && $month > 0 && $month <= 12) {
                    $where[] = $wpdb->prepare('YEAR(log_date) = %d AND MONTH(log_date) = %d', $year, $month);
                }
            }
        }

        return $where ? ' WHERE ' . implode(' AND ', $where) : '';
    }

    protected function record_count(): int {
        global $wpdb;

        $sql = "SELECT COUNT(*) FROM $this->table_name";
        $sql .= $this->build_where_clause();

        return (int)$wpdb->get_var($sql);
    }

    public function no_items(): void {
        esc_html_e('No logs available.', 'wp-login-activity');
    }

    private function get_counts(): array {
        global $wpdb;

        $where = [];

        if (!empty($_GET['s'])) {
            $s_raw = wp_unslash($_GET['s']);
            $s = '%' . $wpdb->esc_like(sanitize_text_field($s_raw)) . '%';
            $where[] = $wpdb->prepare('login LIKE %s', $s);
        }

        if (!empty($_GET['date'])) {
            [$year, $month] = array_map('intval', explode('-', sanitize_text_field($_GET['date'])));

            if ($year > 0 && $month > 0 && $month <= 12) {
                $where[] = $wpdb->prepare('YEAR(log_date) = %d AND MONTH(log_date) = %d', $year, $month);
            }
        }

        $where_clause = $where ? ' WHERE ' . implode(' AND ', $where) : '';

        $sql = "
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) AS successes,
                SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) AS errors
            FROM {$this->table_name}
            {$where_clause}
        ";

        return (array)$wpdb->get_row($sql, ARRAY_A);
    }

    protected function get_views(): array {
        $counts = $this->get_counts();
        $all_url = remove_query_arg(['s', 'paged', 'status', 'date']);
        $search_q = !empty($_GET['s']) ? '&s=' . urlencode($_GET['s']) : '';
        $date_q = !empty($_GET['date']) ? '&date=' . urlencode($_GET['date']) : '';
        $base_args = $all_url . $search_q . $date_q;

        $all_class = !isset($_GET['status']) ? ' class="current"' : '';
        $success_class = (isset($_GET['status']) && $_GET['status'] === 'success') ? ' class="current"' : '';
        $error_class = (isset($_GET['status']) && $_GET['status'] === 'error') ? ' class="current"' : '';

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
                return date_i18n($this->date_format . ', ' . $this->time_format, strtotime($item['log_date']));

            default:
                return esc_html(print_r($item, true));
        }
    }

    public function get_sortable_columns(): array {
        return [
            'log_date' => ['log_date', false]
        ];
    }

    public function get_bulk_actions(): array {
        return [];
    }

    /**
     * Handles data query, filtering, sorting, and pagination.
     */
    public function prepare_items(): void {
        $this->_column_headers = $this->get_column_info();

        $per_page = $this->get_items_per_page('login_logs_per_page', 100);
        $current_page = $this->get_pagenum();
        $total_items = $this->record_count();

        $this->set_pagination_args([
            'total_items' => $total_items,
            'per_page' => $per_page
        ]);

        $this->items = $this->get_login_activity($per_page, $current_page);
    }

    private function display_date_dropdown(): void {
        global $wpdb, $wp_locale;

        $dates = $wpdb->get_results("
            SELECT DISTINCT YEAR(log_date) AS year, MONTH(log_date) AS month
            FROM {$this->table_name}
            ORDER BY log_date DESC
        ");

        $selected_date = $_GET['date'] ?? '';

        ?>

        <label for="filter-by-date" class="screen-reader-text"><?php esc_html_e('Filter by date', 'wp-login-activity'); ?></label>
        <select name="date" id="filter-by-date">
            <option<?php selected($selected_date, 0) ?> value="0"><?php esc_html_e('All dates', 'wp-login-activity') ?></option>

            <?php

            foreach ($dates as $arc_row) {
                if ((int)$arc_row->year === 0) {
                    continue;
                }

                $month = zeroise((int)$arc_row->month, 2);
                $year = (int)$arc_row->year;

                printf(
                    "<option %s value='%s'>%s</option>\n",
                    selected($selected_date, $year . '-' . $month, false),
                    esc_attr($year . '-' . $month),
                    sprintf(
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

    protected function display_tablenav($which): void {
        ?>

        <div class="tablenav <?php echo esc_attr($which); ?>">
            <div class="alignleft actions">
                <?php

                if ($which === 'top') {
                    $this->display_date_dropdown();
                    submit_button(esc_html__('Filter', 'wp-login-activity'), '', 'filter_action', false, ['id' => 'post-query-submit']);
                }

                ?>
            </div>

            <?php

            $this->extra_tablenav($which);
            $this->pagination($which);

            ?>

            <br class="clear"/>
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
        return $value;
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
            <div id="poststuff">
                <div id="post-body" class="metabox-holder columns-1">
                    <div id="post-body-content">
                        <div class="meta-box-sortables ui-sortable">
                            <?php $this->logs_obj->views() ?>
                            <form method="get">
                                <input type="hidden" name="page" value="<?php echo isset($_REQUEST['page']) ? esc_attr($_REQUEST['page']) : ''; ?>"/>
                                <?php
                                $this->logs_obj->prepare_items();
                                $this->logs_obj->search_box(esc_html__('Search login', 'wp-login-activity'), 'login-log');
                                $this->logs_obj->display();
                                ?>
                            </form>
                        </div>
                    </div>
                </div>
                <br class="clear">
            </div>
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
