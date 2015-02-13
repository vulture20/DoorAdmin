namespace DoorAdmin
{
    partial class Form1
    {
        /// <summary>
        /// Erforderliche Designervariable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Verwendete Ressourcen bereinigen.
        /// </summary>
        /// <param name="disposing">True, wenn verwaltete Ressourcen gelöscht werden sollen; andernfalls False.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Vom Windows Form-Designer generierter Code

        /// <summary>
        /// Erforderliche Methode für die Designerunterstützung.
        /// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.toolStripStatusLabel1 = new System.Windows.Forms.ToolStripStatusLabel();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.dateiToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.beendenToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.buzzerToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aktiviertToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.deaktiviertToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.button1 = new System.Windows.Forms.Button();
            this.hexBox1 = new Be.Windows.Forms.HexBox();
            this.button2 = new System.Windows.Forms.Button();
            this.infoToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.versionToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.statusStrip1.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // textBox1
            // 
            this.textBox1.Location = new System.Drawing.Point(12, 393);
            this.textBox1.Multiline = true;
            this.textBox1.Name = "textBox1";
            this.textBox1.ReadOnly = true;
            this.textBox1.Size = new System.Drawing.Size(824, 140);
            this.textBox1.TabIndex = 0;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripStatusLabel1});
            this.statusStrip1.Location = new System.Drawing.Point(0, 536);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(773, 22);
            this.statusStrip1.TabIndex = 1;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            this.toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            this.toolStripStatusLabel1.Size = new System.Drawing.Size(0, 17);
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.dateiToolStripMenuItem,
            this.buzzerToolStripMenuItem,
            this.infoToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(773, 24);
            this.menuStrip1.TabIndex = 5;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // dateiToolStripMenuItem
            // 
            this.dateiToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.beendenToolStripMenuItem});
            this.dateiToolStripMenuItem.Name = "dateiToolStripMenuItem";
            this.dateiToolStripMenuItem.Size = new System.Drawing.Size(46, 20);
            this.dateiToolStripMenuItem.Text = "Datei";
            // 
            // beendenToolStripMenuItem
            // 
            this.beendenToolStripMenuItem.Name = "beendenToolStripMenuItem";
            this.beendenToolStripMenuItem.Size = new System.Drawing.Size(120, 22);
            this.beendenToolStripMenuItem.Text = "Beenden";
            this.beendenToolStripMenuItem.Click += new System.EventHandler(this.beendenToolStripMenuItem_Click);
            // 
            // buzzerToolStripMenuItem
            // 
            this.buzzerToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.aktiviertToolStripMenuItem,
            this.deaktiviertToolStripMenuItem});
            this.buzzerToolStripMenuItem.Name = "buzzerToolStripMenuItem";
            this.buzzerToolStripMenuItem.Size = new System.Drawing.Size(53, 20);
            this.buzzerToolStripMenuItem.Text = "Buzzer";
            // 
            // aktiviertToolStripMenuItem
            // 
            this.aktiviertToolStripMenuItem.Name = "aktiviertToolStripMenuItem";
            this.aktiviertToolStripMenuItem.Size = new System.Drawing.Size(130, 22);
            this.aktiviertToolStripMenuItem.Text = "Aktiviert";
            this.aktiviertToolStripMenuItem.Click += new System.EventHandler(this.aktiviertToolStripMenuItem_Click);
            // 
            // deaktiviertToolStripMenuItem
            // 
            this.deaktiviertToolStripMenuItem.Checked = true;
            this.deaktiviertToolStripMenuItem.CheckState = System.Windows.Forms.CheckState.Checked;
            this.deaktiviertToolStripMenuItem.Name = "deaktiviertToolStripMenuItem";
            this.deaktiviertToolStripMenuItem.Size = new System.Drawing.Size(130, 22);
            this.deaktiviertToolStripMenuItem.Text = "Deaktiviert";
            this.deaktiviertToolStripMenuItem.Click += new System.EventHandler(this.deaktiviertToolStripMenuItem_Click);
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(677, 48);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(75, 23);
            this.button1.TabIndex = 6;
            this.button1.Text = "GetUID";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // hexBox1
            // 
            this.hexBox1.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hexBox1.LineInfoVisible = true;
            this.hexBox1.Location = new System.Drawing.Point(12, 27);
            this.hexBox1.Name = "hexBox1";
            this.hexBox1.ReadOnly = true;
            this.hexBox1.ShadowSelectionColor = System.Drawing.Color.FromArgb(((int)(((byte)(100)))), ((int)(((byte)(60)))), ((int)(((byte)(188)))), ((int)(((byte)(255)))));
            this.hexBox1.Size = new System.Drawing.Size(645, 360);
            this.hexBox1.StringViewVisible = true;
            this.hexBox1.TabIndex = 7;
            this.hexBox1.UseFixedBytesPerLine = true;
            this.hexBox1.VScrollBarVisible = true;
            // 
            // button2
            // 
            this.button2.Location = new System.Drawing.Point(677, 77);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(75, 23);
            this.button2.TabIndex = 8;
            this.button2.Text = "GetData";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // infoToolStripMenuItem
            // 
            this.infoToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.versionToolStripMenuItem});
            this.infoToolStripMenuItem.Name = "infoToolStripMenuItem";
            this.infoToolStripMenuItem.Size = new System.Drawing.Size(40, 20);
            this.infoToolStripMenuItem.Text = "Info";
            // 
            // versionToolStripMenuItem
            // 
            this.versionToolStripMenuItem.Name = "versionToolStripMenuItem";
            this.versionToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.versionToolStripMenuItem.Text = "Version";
            this.versionToolStripMenuItem.Click += new System.EventHandler(this.versionToolStripMenuItem_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(773, 558);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.hexBox1);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.menuStrip1);
            this.Controls.Add(this.textBox1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "Form1";
            this.Text = "DoorAdmin";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.Form1_FormClosing);
            this.Load += new System.EventHandler(this.Form1_Load);
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem dateiToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem buzzerToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aktiviertToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem deaktiviertToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem beendenToolStripMenuItem;
        private System.Windows.Forms.Button button1;
        private Be.Windows.Forms.HexBox hexBox1;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.ToolStripMenuItem infoToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem versionToolStripMenuItem;

    }
}

