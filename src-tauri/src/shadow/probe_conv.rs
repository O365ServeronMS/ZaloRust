//! Final discriminator: conv types + per-conv message counts.
use super::golden::open_live;

#[test]
#[ignore]
fn probe_conv_types() {
    let live = open_live();
    for id in ["3488546127013384456", "4006768326137472507", "5162217022126664898", "4807758009819181785", "-1"] {
        let row: Option<(i64, i64, Option<String>)> = live
            .query_row(
                "SELECT type, unread, title FROM conversations WHERE id = ?1",
                [id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<String>>(2)?)),
            )
            .ok();
        let n: i64 = live
            .query_row("SELECT COUNT(*) FROM messages WHERE conv_id = ?1", [id], |r| r.get(0))
            .unwrap_or(0);
        let senders: i64 = live
            .query_row(
                "SELECT COUNT(DISTINCT sender_id) FROM messages WHERE conv_id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        // Title presence only (never the value).
        let has_title = row.as_ref().map(|r| r.2.is_some());
        println!("CONV {id}: exists={:?} type={:?} unread={:?} has_title={:?} msgs={n} distinct_senders={senders}",
            row.is_some(),
            row.as_ref().map(|r| r.0),
            row.as_ref().and_then(|r| Some(r.1)),
            has_title,
        );
    }
    // Global: how many group-type convs have messages, and do group msgs'
    // senders match uidFrom (sample counts only)?
    let groups: i64 = live
        .query_row("SELECT COUNT(*) FROM conversations WHERE type = 1", [], |r| r.get(0))
        .unwrap();
    let group_msgs: i64 = live
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE conv_id IN (SELECT id FROM conversations WHERE type = 1)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let self_sender: i64 = live
        .query_row("SELECT COUNT(*) FROM messages WHERE sender_id = '2294947733392101048'", [], |r| r.get(0))
        .unwrap();
    let self_uid8: i64 = live
        .query_row("SELECT COUNT(*) FROM messages WHERE sender_id = '3488546127013384456'", [], |r| r.get(0))
        .unwrap();
    println!("SUMMARY: group_convs={groups} group_msgs={group_msgs} sender=2294...:{self_sender} sender=3488...:{self_uid8}");
}
