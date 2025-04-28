import pygal
from src.tp1.utils.config import logger
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "Protocol Capture Report\n"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        """
        Properly save the report as a real PDF using reportlab
        """
        c = canvas.Canvas(filename, pagesize=letter)
        width, height = letter

        # Starting y position
        y = height - 50

        # Add Title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, self.title.strip())
        y -= 40

        # Add Summary
        c.setFont("Helvetica", 12)
        for line in self.summary.splitlines():
            c.drawString(50, y, line)
            y -= 20

        # Add Table
        for line in self.array.splitlines():
            c.drawString(50, y, line)
            y -= 20

        c.save()
        logger.info(f"Real PDF saved at {filename}")

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        protocols = self.capture.get_all_protocols()

        if param == "graph":
            # TODO: generate graph
            chart = pygal.Pie()
            chart.title = 'Protocol Distribution'
            for proto, count in protocols.items():
                chart.add(proto, count)

            # Save the chart to a file
            chart_file = self.filename.replace(".pdf", "_chart.svg")
            chart.render_to_file(chart_file)
            self.graph = f"Graph saved to: {chart_file}"
            logger.info(f"Protocol graph generated at {chart_file}")

        elif param == "array":
            # TODO: generate array
            table = "\nProtocole | Nombre de paquets\n"
            table += "-" * 30 + "\n"
            for proto, count in protocols.items():
                table += f"{proto:<10} | {count}\n"
            self.array = table
            logger.info("Protocol table generated")
