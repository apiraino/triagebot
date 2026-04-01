use tera::{Context, Tera};

fn main() {
    let tpl_contents = include_str!("../../templates/test.tt");
    let mut tera = Tera::default();
    tera.add_raw_templates(vec![("whatever", &tpl_contents)])
        .unwrap();
    dbg!(&tera.get_template_names().collect::<Vec<&str>>());

    let mut context = Context::new();
    context.insert("age", &18);

    let output = tera.render("whatever", &context).unwrap();
    dbg!(&output);
}
